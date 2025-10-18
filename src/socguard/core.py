import os
import sys
import time
import getpass
from pathlib import Path
from typing import Optional, Tuple

from .utils import (
    ensure_dir, sha256_file, parse_sha256_sidecar,
    pick_latest_remote_zip_cmd, read_file_as_base64_chunks_ps, write_bytes_from_base64_lines,
    windows_escape_path, ps_to_encoded
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
        script_path: str = r"C:\ProgramData\SOCguard\work\Collect-WindowsLogs.ps1",
        remote_output_dir: str = r"C:\ProgramData\SOCguard\out",
        winrm_port: int = 5986,
        winrm_insecure: bool = False,
        winrm_ca: Optional[str] = None,
        ssh_port: int = 22,
        ssh_host_key_policy: str = "warning",  # warning | reject | autoadd
        known_hosts: Optional[str] = None,
        timeout: int = 600,
        script_url: Optional[str] = None,
        remote_workdir: str = r"C:\ProgramData\SOCguard",
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

        # New: optional GitHub Raw download mode
        self.script_url = script_url
        self.remote_workdir = remote_workdir

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

    # ---------- HELPERS ----------
    def _ps_prep_script_from_url(self) -> Tuple[str, str, str]:
        """
        Returns (ps_script_text, remote_script_path, remote_output_dir).

        The PowerShell script:
          - creates working dirs under self.remote_workdir
          - downloads the script from self.script_url into work\Collect-WindowsLogs.ps1
          - ensures output dir exists at out\
        """
        work = rf"{self.remote_workdir}\work"
        out  = rf"{self.remote_workdir}\out"
        script_path = rf"{work}\Collect-WindowsLogs.ps1"
        url = (self.script_url or "").replace('"','`"')

        ps = rf"""
$ErrorActionPreference='Stop'
New-Item -ItemType Directory -Force -Path '{self.remote_workdir}' | Out-Null
New-Item -ItemType Directory -Force -Path '{work}' | Out-Null
New-Item -ItemType Directory -Force -Path '{out}'  | Out-Null

try {{
  Invoke-WebRequest -Uri "{url}" -OutFile "{script_path}" -UseBasicParsing
}} catch {{
  throw "Failed to download collector from GitHub: $($_.Exception.Message)"
}}

"{script_path}"
"{out}"
"""
        return ps.strip(), script_path, out

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

        # 1) Prepare script (optional)
        if self.script_url:
            print("[*] Preparing remote script from GitHub Raw...")
            ps_prep, remote_script_path, remote_outdir = self._ps_prep_script_from_url()
            stdout, stderr, rc = client.run_ps(ps_prep)
            if rc != 0:
                print(stderr or stdout)
                raise SystemExit("Failed to prepare remote script from URL.")
            script_to_run = remote_script_path
            outdir_to_use = remote_outdir
        else:
            script_to_run = self.script_path
            outdir_to_use = self.remote_output_dir

        # 2) Trigger Windows script
        print("[*] Running remote PowerShell collector...")
        ps_run = rf"""
$ErrorActionPreference='Stop'
& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{script_to_run}" -OutputDirectory "{outdir_to_use}" -Format CSV
if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}
"""
        stdout, stderr, rc = client.run_ps(ps_run)
        if rc != 0:
            print(stderr or stdout)
            raise SystemExit(f"Remote collector failed with code {rc}")

        # 3) Find latest ZIP + sha256
        print("[*] Locating newest ZIP on remote...")
        ps_list = pick_latest_remote_zip_cmd(outdir_to_use)
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

        # 4) Download (chunked Base64)
        local_zip = str(Path(self.output_dir) / Path(remote_zip).name)
        print("[*] Downloading ZIP (chunked base64 over WinRM)...")
        ps_dl = read_file_as_base64_chunks_ps(remote_zip)
        stdout, stderr, rc = client.run_ps(ps_dl)
        if rc != 0:
            print(stderr[:5000] if stderr else "")
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
            # 1) Prepare script (optional): download from GitHub Raw on the remote host
            if self.script_url:
                print("[*] Preparing remote script from GitHub Raw (SSH path)...")
                ps_prep, remote_script_path, remote_outdir = self._ps_prep_script_from_url()
                enc = ps_to_encoded(ps_prep)
                cmd = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {enc}"
                out, err, rc = cli.run_cmd(cmd)
                if rc != 0:
                    print(out or err)
                    raise SystemExit("Failed to prepare remote script from URL (SSH).")
                script_to_run = remote_script_path
                outdir_to_use = remote_outdir
            else:
                script_to_run = self.script_path
                outdir_to_use = self.remote_output_dir

            # 2) Run the collector via -EncodedCommand to avoid quoting issues
            print("[*] Running remote PowerShell collector over SSH...")
            ps_run = rf"""
$ErrorActionPreference='Stop'
& "{script_to_run}" -OutputDirectory "{outdir_to_use}" -Format CSV
if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}
"""
            enc_run = ps_to_encoded(ps_run)
            cmd = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {enc_run}"
            out, err, rc = cli.run_cmd(cmd)
            if rc != 0:
                print(out or err)
                raise SystemExit(f"Remote collector failed with code {rc}")

            # 3) Locate newest ZIP
            print("[*] Locating newest ZIP on remote...")
            ps = pick_latest_remote_zip_cmd(outdir_to_use)
            enc_list = ps_to_encoded(ps)
            cmd = f"powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand {enc_list}"
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

            # 4) Download files via SFTP
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
