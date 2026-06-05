import os
import tempfile
from datetime import datetime
import concurrent.futures
from transport.ssh import SSHManager
from hunting.models import Report
from hunting.checks import run_all_checks, check_complex_correlation, load_rules

class HuntEngine:
    def __init__(self, vm_configs: list[dict]):
        self.vm_configs = vm_configs

        # Dynamically extract all unique target logs from the rules file
        self.required_logs = self._get_required_logs()

    def _get_required_logs(self) -> set:
        """Parses rules.json to dynamically determine which log files need to be fetched."""
        logs = set()
        rules = load_rules()

        for rule in rules:
            for log_path in rule.get("target_logs", []):
                logs.add(log_path)

        # Ensure default security logs are always included
        # for complex correlation analysis
        logs.update(["/var/log/auth.log", "/var/log/secure"])
        return logs

    def hunt_single_vm(self, config: dict) -> Report:
        """Executes the threat hunting workflow on a single target machine."""
        vm_name = config.get("name", "Unknown_VM")
        print(f"[*] Initiating threat hunt on target: {vm_name}...")

        findings = []
        status = "Success"
        error_message = ""

        # Create a local temporary directory to store collected evidence
        temp_dir = tempfile.mkdtemp(prefix=f"hunt_{vm_name}_")

        ssh = SSHManager(
            host=config.get("host"),
            port=config.get("port", 22),
            username=config.get("username"),
            key_path=config.get("key_path"),
            password=config.get("password")
        )

        if not ssh.test_connection():
            return Report(
                vm_name=vm_name,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                findings=[],
                status="Error",
                error_message="SSH Connection Failed - Target Unreachable"
            )

        try:
            # Fetch only the log files required by the active detection rules
            for remote_path in self.required_logs:
                local_path = ssh.fetch_log_file(remote_path, temp_dir)

                # Verify file existence and integrity before parsing
                if local_path and os.path.exists(local_path) and os.path.getsize(local_path) > 0:
                    with open(local_path, 'r', encoding='latin-1') as f:
                        content = f.read()

                    # Run pattern-based detections and correlation analysis
                    findings.extend(run_all_checks(content, remote_path))
                    findings.extend(check_complex_correlation(content, remote_path))

        except Exception as e:
            status = "Error"
            error_message = f"Analysis Exception: {str(e)}"
            print(f"[!] Error during hunt on {vm_name}: {e}")

        finally:
            ssh.close()

        return Report(
            vm_name=vm_name,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            findings=findings,
            status=status,
            error_message=error_message
        )

    def hunt_all_vms(self) -> list[Report]:
        """Executes hunting operations concurrently across all configured VMs."""
        reports = []

        # Calculate the optimal number of worker threads
        workers = len(self.vm_configs) if len(self.vm_configs) > 0 else 1

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_vm = {
                executor.submit(self.hunt_single_vm, vm): vm
                for vm in self.vm_configs
            }

            for future in concurrent.futures.as_completed(future_to_vm):
                try:
                    reports.append(future.result())

                except Exception as exc:
                    # Handle worker thread failures without stopping execution
                    print(f"[!] Worker thread exception: {exc}")

        return reports