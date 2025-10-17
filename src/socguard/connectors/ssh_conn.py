import paramiko
from typing import Tuple

class SSHClient:
    def __init__(self, host: str, username: str, password: str | None,
                 port: int = 22, key_filename: str | None = None,
                 host_key_policy: str = "warning", known_hosts: str | None = None, timeout: int = 30):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_filename = key_filename
        self.timeout = timeout
        self.ssh = paramiko.SSHClient()
        if host_key_policy == "reject":
            self.ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        elif host_key_policy == "autoadd":
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            self.ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        if known_hosts:
            self.ssh.load_host_keys(known_hosts)

    def connect(self):
        self.ssh.connect(
            self.host, port=self.port, username=self.username,
            password=self.password, key_filename=self.key_filename,
            look_for_keys=False if self.key_filename or self.password else True,
            timeout=self.timeout,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
        )

    def run_cmd(self, cmd: str) -> Tuple[str, str, int]:
        stdin, stdout, stderr = self.ssh.exec_command(cmd, timeout=self.timeout)
        out = stdout.read().decode(errors="ignore")
        err = stderr.read().decode(errors="ignore")
        rc = stdout.channel.recv_exit_status()
        return out, err, rc

    def sftp_get(self, remote_path: str, local_path: str):
        sftp = self.ssh.open_sftp()
        try:
            sftp.get(remote_path, local_path)
        finally:
            sftp.close()

    def close(self):
        try:
            self.ssh.close()
        except Exception:
            pass
