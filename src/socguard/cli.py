import argparse
import sys
from .core import SocGuard
from .version import __version__

def build_parser():
    p = argparse.ArgumentParser(
        prog="socguard",
        description="SOCguard: Remote Windows log collection orchestrator (WinRM HTTPS / SSH)"
    )
    p.add_argument("--target", required=True, help="Windows host/IP")
    p.add_argument("--output", required=True, help="Local output directory on Linux")
    p.add_argument("--script-path", default=r"C:\Tools\Lab\Collect-WindowsLogs.ps1", help="Remote path to your existing PowerShell script")
    p.add_argument("--remote-output-dir", default=r"C:\Tools\Lab", help="Remote directory where logs are saved")
    p.add_argument("--username", help="Remote username")
    p.add_argument("--password", help="Remote password (omit to be prompted)")
    p.add_argument("--key-file", help="SSH private key path (SSH only)")
    p.add_argument("--transport", choices=["auto", "winrm", "ssh"], default="auto", help="Connection method")
    # WinRM
    p.add_argument("--winrm-port", type=int, default=5986)
    p.add_argument("--winrm-insecure", action="store_true", help="Do not validate WinRM TLS certificate (NOT recommended)")
    p.add_argument("--winrm-ca", help="Path to CA bundle for WinRM TLS validation")
    # SSH
    p.add_argument("--ssh-port", type=int, default=22)
    p.add_argument("--ssh-host-key-policy", choices=["warning","reject","autoadd"], default="warning")
    p.add_argument("--known-hosts", help="Path to known_hosts file")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p

def main(argv=None):
    args = build_parser().parse_args(argv)
    sg = SocGuard(
        target=args.target,
        output_dir=args.output,
        transport=args.transport,
        username=args.username,
        password=args.password,
        key_file=args.key_file,
        script_path=args.script_path,
        remote_output_dir=args.remote_output_dir,
        winrm_port=args.winrm_port,
        winrm_insecure=args.winrm_insecure,
        winrm_ca=args.winrm_ca,
        ssh_port=args.ssh_port,
        ssh_host_key_policy=args.ssh_host_key_policy,
        known_hosts=args.known_hosts,
    )
    return sg.run()

if __name__ == "__main__":
    sys.exit(main())
