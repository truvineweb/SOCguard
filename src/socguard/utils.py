import hashlib
import os
import re
from pathlib import Path

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def parse_sha256_sidecar(path: str) -> str | None:
    """
    Accepts common formats (our Windows script writes lines like 'SHA256: <hash>').
    """
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except FileNotFoundError:
        return None

    # Try lines like 'SHA256: <hex>'
    m = re.search(r"SHA256:\s*([A-Fa-f0-9]{64})", text)
    if m:
        return m.group(1)

    # Try generic '([hex])' lines
    m = re.search(r"\b([A-Fa-f0-9]{64})\b", text)
    return m.group(1) if m else None

def ensure_dir(p: str):
    Path(p).mkdir(parents=True, exist_ok=True)

def windows_escape_path(p: str) -> str:
    # Quote for PowerShell
    p = p.replace("`", "``").replace('"', '`"')
    return f'"{p}"'

def pick_latest_remote_zip_cmd(output_dir: str) -> str:
    # PowerShell picks latest System_Logs_*.zip + accompanying sha256 file
    out_dir = windows_escape_path(output_dir)
    ps = rf"""
$ErrorActionPreference='Stop'
$zip = Get-ChildItem -LiteralPath {out_dir} -Filter 'System_Logs_*.zip' -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($null -eq $zip) {{ Write-Output 'ZIP=NULL'; exit 0 }}
$hash = $null
$sha = Get-ChildItem -LiteralPath $zip.DirectoryName -Filter ('{0}.sha256.txt' -f ($zip.BaseName)) -File -ErrorAction SilentlyContinue | Select-Object -First 1
$zip.FullName
if ($sha) {{ $sha.FullName }} else {{ 'SHA=NULL' }}
"""
    return ps.strip()

def read_file_as_base64_chunks_ps(remote_path: str, chunk_size: int = 1024 * 1024) -> str:
    rp = windows_escape_path(remote_path)
    return rf"""
$ErrorActionPreference='Stop'
function Read-FileBase64 {{
  param([string]$Path,[int]$ChunkSize)
  $fs=[IO.File]::OpenRead($Path)
  $buf=New-Object byte[] $ChunkSize
  try {{
    while(($read=$fs.Read($buf,0,$buf.Length)) -gt 0) {{
      [Convert]::ToBase64String($buf,0,$read)
    }}
  }} finally {{ $fs.Close() }}
}}
Read-FileBase64 -Path {rp} -ChunkSize {chunk_size}
""".strip()

def write_bytes_from_base64_lines(lines, local_path: str):
    import base64
    with open(local_path, "wb") as f:
        for line in lines:
            if not line:
                continue
            f.write(base64.b64decode(line.strip()))
