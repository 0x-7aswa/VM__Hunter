import os
from fabric import Connection, Config
import tempfile

class SSHManager:
    def __init__(self, host: str, port: int, username: str, key_path: str = None, password: str = None):
        self.host = host
        self.password = password
        connect_kwargs = {}
        
        # Configure authentication method (Key-based or Password-based)
        if key_path:
            connect_kwargs["key_filename"] = os.path.expanduser(key_path)
        if password:
            connect_kwargs["password"] = password

        # Enforce latin-1 encoding to prevent decoding errors (e.g., 0xd1 on Linux Mint)
        custom_config = Config(overrides={
            'run': {'encoding': 'latin-1'},
            'sudo': {'encoding': 'latin-1'}
        })

        self.conn = Connection(
            host=host,
            user=username,
            port=port,
            connect_kwargs=connect_kwargs,
            connect_timeout=10,
            config=custom_config
        )
    
    def test_connection(self) -> bool:
        """Tests if the target VM is reachable and SSH is operational."""
        try:
            result = self.conn.run("hostname && uptime", hide=True, warn=True)
            return result.ok
        except Exception:
            return False

    def fetch_log_file(self, remote_path: str, local_dir: str) -> str:
        """
        Safely copies a remote log file to a temporary location, downloads it,
        and cleans up the remote temporary file. Returns the local path.
        """
        try:
            # Resolve relative paths (e.g., ~/.bash_history) to absolute paths
            if remote_path.startswith("~/"):
                res = self.conn.run(f"echo {remote_path}", hide=True, warn=True)
                if res.ok and res.stdout.strip():
                    remote_path = res.stdout.strip()

            local_path = os.path.join(local_dir, os.path.basename(remote_path))
            # Create a unique temporary filename on the remote host
            tmp_remote = f"/tmp/{os.path.basename(remote_path)}_{os.urandom(4).hex()}.tmp"
            
            copy_cmd = f"cp {remote_path} {tmp_remote} && chmod 644 {tmp_remote}"
            
            # Smart privilege handling: Try with sudo if password exists, else fallback
            if self.password:
                self.conn.run(f"echo '{self.password}' | sudo -S sh -c '{copy_cmd}'", hide=True, warn=True)
            else:
                self.conn.run(f"sudo sh -c '{copy_cmd}' || sh -c '{copy_cmd}'", hide=True, warn=True)

            # Verify if the file was successfully copied to /tmp before downloading
            check_cmd = self.conn.run(f"ls {tmp_remote}", hide=True, warn=True)
            if check_cmd.ok:
                self.conn.get(remote=tmp_remote, local=local_path)
                
                # Cleanup remote temporary file
                if self.password:
                    self.conn.run(f"echo '{self.password}' | sudo -S rm -f {tmp_remote}", hide=True, warn=True)
                else:
                    self.conn.run(f"sudo rm -f {tmp_remote} || rm -f {tmp_remote}", hide=True, warn=True)
                
                return local_path
            else:
                return None
                
        except Exception as e:
            # Silently handle missing files to maintain stealth and stability
            return None

    def close(self):
        """Closes the SSH connection gracefully."""
        try:
            self.conn.close()
        except Exception:
            pass