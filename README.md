# SOCguard
Socguard is an open-source Linux security tool that monitors real-time threats, detects network anomalies, and automates incident responses. It integrates with Ubuntu, Fedora,&amp;CentOS, featuring customizable alerts, log analysis, and vulnerability scanning. Ideal for personal servers or enterprises, it ensures robust cybersecurity with low overhead.

# SOCguard

**SOCguard** securely triggers your existing Windows PowerShell collector script (`Collect-WindowsLogs.ps1`) from Linux, then downloads and verifies the logs. Works over **WinRM (HTTPS)** or **SSH**.

## Imagine this like…

- **Connect:** like calling your friend using a secret phone line (WinRM HTTPS) or walkie-talkie (SSH).
- **Collect:** you tell them to press the “collect logs” button (runs your PowerShell script).
- **Download:** they leave a box at the door (ZIP file), you pick it up.
- **Verify:** you check the box’s sticker (SHA-256) so nothing got swapped.

## Features

- WinRM over **HTTPS** (default) with certificate validation
- Optional **SSH**/SFTP path
- Works with your existing `Collect-WindowsLogs.ps1`
- **Integrity** verification (SHA-256)
- Kali-friendly install (pipx one-liner) and `.deb` build script
- Clear, friendly CLI: `socguard --help`

## Install (easy one-liner)

```bash
curl -fsSL https://raw.githubusercontent.com/<your-user>/socguard/main/install.sh | bash
