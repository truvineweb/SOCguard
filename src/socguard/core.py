import os
import sys
import time
import getpass
from pathlib import Path
from typing import Optional, Tuple

from .utils import (
    ensure_dir, sha256_file, parse_sha256_sidecar,
    pick_latest_remote_zip_cmd, read_file_as_base64_chunks_ps, write_bytes_from_base64_lines, windows_escape_path
)
from .connectors.winrm_conn import WinRMClient
from .connectors.ssh_conn import SSHClient

class SocGuard:
    def __init__(
        self,
        target: str,
        output_dir: str,
        transport: str = "auto",             # auto | winrm | ssh
        username: Optional[str] = None,
        password: Optional[str] = None,
        key_file: Optional[str] = None,
        script_path: str = r"C:\Tools\Lab\Collect-WindowsLogs.ps1",
        remote_output_dir: str = r"C:\Tools\Lab",
        winrm_port: int = 5986,
        winrm_insecure: bool = False,
        winrm_ca: Optional[str] = None,
        ssh_port: int = 22,
        ssh_host_key_policy: str = "warning",  # warning | reject | autoadd
        known_hosts: Optional[str] = None,
        timeout: int = 600,
    ):
        self.target = target
        self.output_dir = output_dir
        self.transport = transport
        self.username = username
        self.password = password
        self.key_file = key_file
        self.script_path = script_path
        self.remote_output_dir = remote_output_dir
        self.winrm_port = winrm_port
        self.winrm_insecure = winrm_insecure
        self.winrm_ca = winrm_ca
        self.ssh_port = ssh_port
        self.ssh_host_key_policy = ssh_host_key_policy
        self.known_hosts = known_hosts
        self.timeout = timeout

        ensure_dir(self.output_dir)

    # ---------- MAIN WORKFLOW ----------
    def run(self) -> int:
        print("[*] Starting SOCguard workflow")
        method = self._choose_transport()
        print(f"[*] Selected transport: {method.upper()}")

        if method == "winrm":
            return self._run_over_winrm()
        else:
            return self._run_over_ssh()

    # ---------- TRANSPORT CHOICE ----------
    def _choose_transport(self) -> str:
        if self.transport in ("winrm", "ssh"):
            return self.transport
        # 'auto': prefer WinRM 5986 first by trying a quick TCP connect
        import socket
        try:
            with socket.create_connection((self.target, self.winrm_port), timeout=3):
                return "winrm"
        except Exception:
            pass
        # Fallback to SSH
        return "ssh"

    # ---------- RUN OVER WINRM ----------
    def _run_over_winrm(self) -> int:
        if not self.username:
            raise SystemExit("Username is required for WinRM.")
        if self.password is None:
            self.password = getpass.getpass("Password: ")

        client = WinRMClient(
            host=self.target,
            username=self.username,
            password=self.password,
            port=self.winrm_port,
            ssl=True,
            cert_validation=not self.winrm_insecure,
            ca_trust_path=self.winrm_ca,
            negotiate=True,
        )

        # 1) Trigger Windows script
        print("[*] Running remote PowerShell collector...")
        script = windows_escape_path(self.script_path)
        outdir = windows_escape_path(self.remote_output_dir)
        ps = rf"""
$ErrorActionPreference='Stop'
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {script} -OutputDirectory {outdir} -Format CSV
if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}
"""
        stdout, stderr, rc = client.run_ps(ps)
        if rc != 0:
            print(stderr or stdout)
            raise SystemExit(f"Remote collector failed with code {rc}")

        # 2) Find latest ZIP + sha256
        print("[*] Locating newest ZIP on remote...")
        ps_list = pick_latest_remote_zip_cmd(self.remote_output_dir)
        stdout, stderr, rc = client.run_ps(ps_list)
        if rc != 0:
            print(stderr or stdout)
            raise SystemExit("Failed to query remote logs.")
        lines = [l.strip() for l in stdout.splitlines() if l.strip()]
        if not lines or lines[0] == "ZIP=NULL":
            raise SystemExit("No ZIP found on remote output directory.")

        remote_zip = lines[0]
        remote_sha = None if len(lines) < 2 or lines[1] == "SHA=NULL" else lines[1]
        print(f"    ZIP: {remote_zip}")
        if remote_sha:
            print(f"    SHA: {remote_sha}")

        # 3) Download (chunked Base64)
        local_zip = str(Path(self.output_dir) / Path(remote_zip).name)
        print("[*] Downloading ZIP (chunked base64 over WinRM)...")
        ps_dl = read_file_as_base64_chunks_ps(remote_zip)
        stdout, stderr, rc = client.run_ps(ps_dl)
        if rc != 0:
            print(stderr[:5000])
            raise SystemExit("Failed downloading zip via WinRM.")
        write_bytes_from_base64_lines(stdout.splitlines(), local_zip)

        local_sha = None
        if remote_sha:
            print("[*] Downloading SHA256 sidecar...")
            ps_dl2 = read_file_as_base64_chunks_ps(remote_sha)
            stdout, stderr, rc = client.run_ps(ps_dl2)
            if rc == 0:
                local_sha = str(Path(self.output_dir) / Path(remote_sha).name)
                write_bytes_from_base64_lines(stdout.splitlines(), local_sha)
            else:
                print("[!] Could not download .sha256.txt, will compute locally.")

        return self._verify(local_zip, local_sha)

    # ---------- RUN OVER SSH ----------
    def _run_over_ssh(self) -> int:
        if not self.username:
            raise SystemExit("Username is required for SSH.")
        if (self.password is None) and (self.key_file is None):
            # Prefer key auth; prompt only if neither was supplied
            try:
                self.password = getpass.getpass("Password (leave empty to try agent/keys): ")
                if not self.password:
                    self.password = None
            except Exception:
                pass

        cli = SSHClient(
            host=self.target,
            username=self.username,
            password=self.password,
            port=self.ssh_port,
            key_filename=self.key_file,
            host_key_policy=self.ssh_host_key_policy,
            known_hosts=self.known_hosts,
        )
        cli.connect()

        try:
            print("[*] Running remote PowerShell collector over SSH...")
            script = self.script_path.replace('"', '\\"')
            outdir = self.remote_output_dir.replace('"', '\\"')
            cmd = f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script}" -OutputDirectory "{outdir}" -Format CSV'
            out, err, rc = cli.run_cmd(cmd)
            if rc != 0:
                print(out or err)
                raise SystemExit(f"Remote collector failed with code {rc}")

            print("[*] Locating newest ZIP on remote...")
            ps = pick_latest_remote_zip_cmd(self.remote_output_dir)
            cmd = f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "{ps.replace("\"", "`\"")}"'
            out, err, rc = cli.run_cmd(cmd)
            if rc != 0:
                print(out or err)
                raise SystemExit("Failed to query remote logs.")
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if not lines or lines[0] == "ZIP=NULL":
                raise SystemExit("No ZIP found on remote output directory.")

            remote_zip = lines[0]
            remote_sha = None if len(lines) < 2 or lines[1] == "SHA=NULL" else lines[1]
            print(f"    ZIP: {remote_zip}")
            if remote_sha:
                print(f"    SHA: {remote_sha}")

            local_zip = str(Path(self.output_dir) / Path(remote_zip).name)
            print("[*] Downloading ZIP via SFTP...")
            cli.sftp_get(remote_zip, local_zip)

            local_sha = None
            if remote_sha:
                try:
                    print("[*] Downloading SHA256 sidecar via SFTP...")
                    local_sha = str(Path(self.output_dir) / Path(remote_sha).name)
                    cli.sftp_get(remote_sha, local_sha)
                except Exception:
                    print("[!] Could not download .sha256.txt, will compute locally.")

            return self._verify(local_zip, local_sha)
        finally:
            cli.close()

    # ---------- VERIFY ----------
    def _verify(self, local_zip: str, local_sha: Optional[str]) -> int:
        print("[*] Verifying integrity...")
        computed = sha256_file(local_zip)
        expected = parse_sha256_sidecar(local_sha) if local_sha else None

        if expected:
            if computed.lower() == expected.lower():
                print(f"[OK] SHA-256 matches: {computed}")
                return 0
            else:
                print(f"[FAIL] SHA-256 mismatch!\n  expected: {expected}\n  computed: {computed}")
                return 2
        else:
            print(f"[i] No sidecar hash provided. Computed SHA-256: {computed}")
            # Save our own sidecar for provenance
            sidecar = f"{local_zip}.sha256.txt"
            Path(sidecar).write_text(f"SHA256: {computed}\nFile: {Path(local_zip).name}\n", encoding="utf-8")
            print(f"[i] Wrote local sidecar: {sidecar}")
            return 0
