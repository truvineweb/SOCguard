[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [ValidateSet('CSV','JSON')]
    [string]$Format = 'CSV',
    [ValidateRange(1, [int]::MaxValue)]
    [int]$TimeRangeHours = 24,
    [int[]]$EventIDs,
    [string]$CertificatePath
)

$ErrorActionPreference = 'Stop'
$RunTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'

if ($TimeRangeHours -lt 1) {
    Write-Host "Invalid TimeRangeHours ($TimeRangeHours). Falling back to 24." -ForegroundColor Yellow
    $TimeRangeHours = 24
}

if (-not $OutputDirectory) {
    $userInput = Read-Host "Enter output directory (leave blank for current directory)"
    if ([string]::IsNullOrWhiteSpace($userInput)) {
        $OutputDirectory = (Get-Location).Path
    } else {
        $OutputDirectory = $userInput
    }
}

try {
    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
} catch {
    Write-Host "ERROR: Could not create or access the output directory: $OutputDirectory" -ForegroundColor Red
    throw
}

$script:LogFile = Join-Path $OutputDirectory ("Script_Execution_Log_{0}.txt" -f $RunTimestamp)

function Write-Log {
    param(
        [ValidateSet('INFO','WARN','ERROR','SUCCESS')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory=$true)][string]$Message
    )
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line = "[{0}][{1}] {2}" -f $ts, $Level, $Message
    try {
        Add-Content -Path $script:LogFile -Value $line
    } catch { }
    switch ($Level) {
        'ERROR'   { Write-Host $line -ForegroundColor Red }
        'WARN'    { Write-Host $line -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $line -ForegroundColor Green }
        default   { Write-Host $line }
    }
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Log -Level WARN -Message "Failed to determine elevation status: $($_.Exception.Message)"
        return $false
    }
}

function Convert-SidToAccount {
    param([System.Security.Principal.SecurityIdentifier]$Sid)
    if (-not $Sid) { return $null }
    try {
        return $Sid.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        return $Sid.Value
    }
}

function Test-StructuredFile {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [ValidateSet('CSV','JSON')][string]$Format
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) { return $false }
        $fi = Get-Item -LiteralPath $Path
        if ($fi.Length -le 0) { return $false }
        switch ($Format) {
            'CSV' {
                try {
                    $rows = Import-Csv -LiteralPath $Path -ErrorAction Stop
                    if ($null -eq $rows) { return $false }
                    return ($rows.Count -ge 1)
                } catch { return $false }
            }
            'JSON' {
                try {
                    $json = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ($null -eq $json) { return $false }
                    if ($json -is [System.Collections.IEnumerable]) {
                        foreach ($i in $json) { return $true }
                        return $false
                    } else {
                        return ($json.PSObject.Properties.Count -gt 0)
                    }
                } catch { return $false }
            }
        }
    } catch { return $false }
}

function New-Placeholder {
    param(
        [Parameter(Mandatory=$true)][string]$Reason,
        [Parameter(Mandatory=$true)][string]$BaseName
    )
    $ph = Join-Path $OutputDirectory ("{0}_{1}_PLACEHOLDER.txt" -f $BaseName, $RunTimestamp)
    $content = @"
Placeholder for $BaseName
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Reason: $Reason
This file was created because the expected data file was missing or empty.
"@
    try {
        Set-Content -LiteralPath $ph -Value $content -Encoding UTF8 -Force
        Write-Log -Level WARN -Message "Created placeholder: $(Split-Path -Leaf $ph) ($Reason)"
    } catch {
        Write-Log -Level ERROR -Message "Failed to create placeholder for $($BaseName): $($_.Exception.Message)"
    }
    return $ph
}

function Export-Structured {
    param(
        [Parameter(Mandatory=$true)][object[]]$Data,
        [Parameter(Mandatory=$true)][string]$BaseName,
        [ValidateSet('CSV','JSON')][string]$Format
    )
    $outPath = Join-Path $OutputDirectory ("{0}_{1}.{2}" -f $BaseName, $RunTimestamp, $Format.ToLower())
    try {
        if ($Format -eq 'CSV') {
            $Data | Export-Csv -LiteralPath $outPath -NoTypeInformation -Encoding UTF8 -Force
        } else {
            $Data | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $outPath -Encoding UTF8 -Force
        }
        Write-Log -Level SUCCESS -Message "Exported $BaseName to $(Split-Path -Leaf $outPath)"
        return $outPath
    } catch {
        Write-Log -Level ERROR -Message "Failed to export $($BaseName): $($_.Exception.Message)"
        return $null
    }
}

Write-Log -Level INFO -Message "Output directory: $OutputDirectory"
Write-Log -Level INFO -Message "Export format: $Format"
Write-Log -Level INFO -Message "Time range: last $TimeRangeHours hours"

if ($EventIDs) {
    Write-Log -Level INFO -Message ("Event ID filter requested: {0}" -f ($EventIDs -join ', '))
} else {
    Write-Log -Level INFO -Message "Event ID filter: (none) — collecting all events within the time range."
}

if ($CertificatePath) { Write-Log -Level INFO -Message "Signing requested using certificate: $CertificatePath" }

$StartTime  = (Get-Date).AddHours(-1 * $TimeRangeHours)
$SysmonBase = 'Sysmon_Logs'
$sysmonPath = $null

try {
    $sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
    if (-not $sysmonLog) {
        Write-Log -Level WARN -Message "Sysmon not installed or the 'Microsoft-Windows-Sysmon/Operational' channel is unavailable."
    } elseif (-not $sysmonLog.IsEnabled) {
        Write-Log -Level WARN -Message "Sysmon channel exists but is disabled."
    } else {
        $sysmonFilter = @{
            LogName   = 'Microsoft-Windows-Sysmon/Operational'
            StartTime = $StartTime
        }
        if ($EventIDs) {
            $sysmonFilter.Id = $EventIDs
            Write-Log -Level INFO -Message ("Applying Sysmon Event ID filter: {0}" -f ($EventIDs -join ', '))
        }
        try {
            $sysmonEvents = Get-WinEvent -FilterHashtable $sysmonFilter -ErrorAction Stop
            if ($sysmonEvents.Count -gt 0) {
                Write-Log -Level INFO -Message ("Sysmon events collected: {0}" -f $sysmonEvents.Count)
                $toExport = $sysmonEvents | Select-Object `
                    TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, RecordId, TaskDisplayName, KeywordsDisplayNames, Message
                $sysmonPath = Export-Structured -Data $toExport -BaseName $SysmonBase -Format $Format
            } else {
                Write-Log -Level WARN -Message "Sysmon channel present, but no events in the requested time range."
            }
        } catch {
            Write-Log -Level ERROR -Message "Reading Sysmon events failed: $($_.Exception.Message)"
        }
    }
} catch {
    Write-Log -Level ERROR -Message "Sysmon detection failed: $($_.Exception.Message)"
}

$SecurityBase  = 'Security_Logs'
$securityPath  = $null
$IsAdmin       = Test-IsAdmin
if (-not $IsAdmin) {
    Write-Log -Level WARN -Message "Not running as Administrator. Access to Security logs may be denied."
}

try {
    $securityEvents = $null
    $securityFilter = @{
        LogName   = 'Security'
        StartTime = $StartTime
    }
    if ($EventIDs) {
        $securityFilter.Id = $EventIDs
        Write-Log -Level INFO -Message ("Applying Security Event ID filter: {0}" -f ($EventIDs -join ', '))
    }
    try {
        $securityEvents = Get-WinEvent -FilterHashtable $securityFilter -ErrorAction Stop
    } catch {
        Write-Log -Level ERROR -Message "Failed to read Security logs. You may need to run this script as Administrator. Error: $($_.Exception.Message)"
    }

    if ($securityEvents -and $securityEvents.Count -gt 0) {
        Write-Log -Level INFO -Message ("Security events collected: {0}" -f $securityEvents.Count)
        $secData = foreach ($ev in $securityEvents) {
            $acct = $null
            try { $acct = Convert-SidToAccount -Sid $ev.UserId } catch { $acct = $null }
            [PSCustomObject]@{
                TimeCreated  = $ev.TimeCreated
                EventId      = $ev.Id
                ProviderName = $ev.ProviderName
                AccountName  = $acct
                MachineName  = $ev.MachineName
                RecordId     = $ev.RecordId
                Message      = $ev.Message
            }
        }
        $securityPath = Export-Structured -Data $secData -BaseName $SecurityBase -Format $Format
    } else {
        Write-Log -Level WARN -Message "No Security events found in the requested time range or access denied."
        if (-not $IsAdmin) {
            Write-Log -Level WARN -Message "Try running PowerShell as Administrator to access the Security event log."
        }
    }
} catch {
    Write-Log -Level ERROR -Message "Security log processing failed: $($_.Exception.Message)"
}

$ProcBase = 'Running_Processes'
$procPath = $null

try {
    $procErrors = New-Object System.Collections.Generic.List[string]
    $procs = Get-Process | ForEach-Object {
        $p = $_
        $path = $null
        try { $path = $p.MainModule.FileName } catch {
            $path = $null
            $procErrors.Add("{0} (PID {1}): {2}" -f $p.ProcessName, $p.Id, $_.Exception.Message)
        }

        # PRE-COMPUTE properties that can throw to avoid using try/catch inside the PSCustomObject literal
        $startTime   = $null; try { $startTime   = $p.StartTime }        catch { $startTime = $null }
        $threadsCnt  = $null; try { $threadsCnt  = $p.Threads.Count }    catch { $threadsCnt = $null }
        $privateMB   = $null; try { if ($p.PrivateMemorySize64) { $privateMB = [Math]::Round(($p.PrivateMemorySize64/1MB), 2) } } catch { $privateMB = $null }

        [PSCustomObject]@{
            ProcessName   = $p.ProcessName
            PID           = $p.Id
            Path          = $path
            CPUSeconds    = $p.CPU
            WorkingSetMB  = [Math]::Round(($p.WorkingSet64/1MB), 2)
            PrivateMB     = $privateMB
            StartTime     = $startTime
            Responding    = $p.Responding
            SessionId     = $p.SessionId
            Handles       = $p.Handles
            Threads       = $threadsCnt
        }
    }

    if ($procErrors.Count -gt 0) {
        Write-Log -Level WARN -Message ("Some processes could not be fully inspected (e.g., path). Count={0}" -f $procErrors.Count)
        foreach ($e in $procErrors | Select-Object -First 10) {
            Write-Log -Level WARN -Message ("Proc access note: {0}" -f $e)
        }
        if ($procErrors.Count -gt 10) {
            Write-Log -Level INFO -Message ("...and {0} more process access notes." -f ($procErrors.Count - 10))
        }
    }

    if ($procs -and $procs.Count -gt 0) {
        $procPath = Export-Structured -Data $procs -BaseName $ProcBase -Format $Format
    } else {
        Write-Log -Level WARN -Message "No running processes were captured (unexpected)."
    }
} catch {
    Write-Log -Level ERROR -Message "Process enumeration failed: $($_.Exception.Message)"
}

$filesForZip = New-Object System.Collections.Generic.List[string]

if ($sysmonPath -and (Test-StructuredFile -Path $sysmonPath -Format $Format)) {
    $filesForZip.Add($sysmonPath) | Out-Null
} else {
    $reason = if (-not $sysmonPath) { "Sysmon data could not be exported (not installed, disabled, empty, or error)." } else { "Export file invalid or empty." }
    $ph = New-Placeholder -Reason $reason -BaseName $SysmonBase
    if (Test-Path -LiteralPath $ph) { $filesForZip.Add($ph) | Out-Null }
}

if ($securityPath -and (Test-StructuredFile -Path $securityPath -Format $Format)) {
    $filesForZip.Add($securityPath) | Out-Null
} else {
    $reason = if (-not $IsAdmin) {
        "Security log access may require Administrator privileges. Rerun as Admin."
    } else {
        "Security data unavailable or export failed/empty."
    }
    $ph = New-Placeholder -Reason $reason -BaseName $SecurityBase
    if (Test-Path -LiteralPath $ph) { $filesForZip.Add($ph) | Out-Null }
}

if ($procPath -and (Test-StructuredFile -Path $procPath -Format $Format)) {
    $filesForZip.Add($procPath) | Out-Null
} else {
    $ph = New-Placeholder -Reason "Process list missing or empty (unexpected)." -BaseName $ProcBase
    if (Test-Path -LiteralPath $ph) { $filesForZip.Add($ph) | Out-Null }
}

$ZipPath = Join-Path $OutputDirectory ("System_Logs_{0}.zip" -f $RunTimestamp)

try {
    if (Test-Path -LiteralPath $ZipPath) {
        Remove-Item -LiteralPath $ZipPath -Force -ErrorAction Stop
    }
    if ($filesForZip.Count -eq 0) {
        $ph = New-Placeholder -Reason "No files to zip; all collections failed." -BaseName "Nothing_To_Zip"
        if (Test-Path -LiteralPath $ph) { $filesForZip.Add($ph) | Out-Null }
    }
    Compress-Archive -Path $filesForZip -DestinationPath $ZipPath -Force
    Write-Log -Level SUCCESS -Message "Created ZIP archive: $(Split-Path -Leaf $ZipPath)"
} catch {
    Write-Log -Level ERROR -Message "Failed to create ZIP archive: $($_.Exception.Message)"
}

$HashPath = $null
if (Test-Path -LiteralPath $ZipPath) {
    try {
        $zipHash = Get-FileHash -Algorithm SHA256 -LiteralPath $ZipPath -ErrorAction Stop
        $HashPath = Join-Path $OutputDirectory ("System_Logs_{0}.sha256.txt" -f $RunTimestamp)
        $hashContent = @"
File: $(Split-Path -Leaf $ZipPath)
Algorithm: $($zipHash.Algorithm)
SHA256: $($zipHash.Hash)
Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@
        Set-Content -LiteralPath $HashPath -Value $hashContent -Encoding UTF8 -Force
        if (Test-Path -LiteralPath $HashPath) {
            Write-Log -Level SUCCESS -Message "Generated SHA-256 hash file: $(Split-Path -Leaf $HashPath)"
        } else {
            Write-Log -Level ERROR -Message "Failed to create SHA-256 hash file."
        }
    } catch {
        Write-Log -Level ERROR -Message "Hashing ZIP failed: $($_.Exception.Message)"
    }
} else {
    Write-Log -Level WARN -Message "Skipping hash: ZIP not present."
}

$CatalogPath = $null
$SignatureStatus = $null

if ($CertificatePath) {
    try {
        if (-not (Test-Path -LiteralPath $CertificatePath)) {
            Write-Log -Level ERROR -Message "CertificatePath not found: $CertificatePath. Skipping signing."
        } elseif (-not (Test-Path -LiteralPath $ZipPath)) {
            Write-Log -Level ERROR -Message "ZIP not found; cannot create a catalog to sign."
        } else {
            $cert = $null
            try {
                $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertificatePath)
                if (-not $cert.HasPrivateKey) {
                    Write-Log -Level ERROR -Message "Provided certificate has no private key. Cannot sign."
                    $cert = $null
                }
            } catch {
                Write-Log -Level ERROR -Message "Failed to import certificate ($CertificatePath). Ensure it’s a PFX with a private key; PowerShell will prompt for password if needed. Error: $($_.Exception.Message)"
            }

            if ($cert -and $cert.HasPrivateKey) {
                try {
                    $CatalogPath = Join-Path $OutputDirectory ("System_Logs_{0}.cat" -f $RunTimestamp)
                    New-FileCatalog -Path $ZipPath -CatalogFilePath $CatalogPath -CatalogVersion 2 -HashAlgorithm SHA256 -ErrorAction Stop
                    Write-Log -Level SUCCESS -Message "Created catalog for signing: $(Split-Path -Leaf $CatalogPath)"

                    $sig = $null
                    try {
                        $sig = Set-AuthenticodeSignature -FilePath $CatalogPath -Certificate $cert -TimestampServer 'http://timestamp.digicert.com' -ErrorAction Stop
                    } catch {
                        Write-Log -Level WARN -Message "Timestamp server failed; retrying without timestamp: $($_.Exception.Message)"
                        $sig = Set-AuthenticodeSignature -FilePath $CatalogPath -Certificate $cert -ErrorAction Stop
                    }

                    $SignatureStatus = $sig.Status
                    Write-Log -Level INFO -Message ("Catalog signature status: {0}" -f $SignatureStatus)
                    $ver = Get-AuthenticodeSignature -FilePath $CatalogPath
                    Write-Log -Level INFO -Message ("Catalog validation status: {0}" -f $ver.Status)
                } catch {
                    Write-Log -Level ERROR -Message "Catalog creation/signing failed: $($_.Exception.Message)"
                }
            } else {
                Write-Log -Level WARN -Message "No usable signing certificate available. Skipping signing."
            }
        }
    } catch {
        Write-Log -Level ERROR -Message "Signing workflow encountered an error: $($_.Exception.Message)"
    }
}

$criticalNotes = @()
if (-not $IsAdmin) {
    $criticalNotes += "Not running as Administrator; Security logs may be incomplete."
}
if (-not (Test-Path -LiteralPath $ZipPath)) {
    $criticalNotes += "ZIP archive was not created."
}
if ($CertificatePath -and -not $CatalogPath) {
    $criticalNotes += "Signing requested, but no catalog was produced (see log)."
}

Write-Host ""
Write-Host "========== Run Complete ==========" -ForegroundColor Cyan
Write-Host ("Output directory : {0}" -f $OutputDirectory)

if (Test-Path -LiteralPath $ZipPath) {
    Write-Host ("ZIP archive      : {0}" -f $ZipPath)
} else {
    Write-Host "ZIP archive      : (not created)" -ForegroundColor Yellow
}

Write-Host ("Log file         : {0}" -f $script:LogFile)

if ($HashPath) {
    Write-Host ("SHA-256 file     : {0}" -f $HashPath)
} else {
    Write-Host "SHA-256 file     : (not created)" -ForegroundColor Yellow
}

if ($CatalogPath) {
    Write-Host ("Catalog (.cat)   : {0}" -f $CatalogPath)
    if ($SignatureStatus) {
        Write-Host ("Signature status : {0}" -f $SignatureStatus)
    }
} elseif ($CertificatePath) {
    Write-Host "Catalog (.cat)   : (signing requested, but not created)" -ForegroundColor Yellow
}

if ($criticalNotes.Count -gt 0) {
    Write-Host "Critical notes   :" -ForegroundColor Yellow
    $criticalNotes | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }
} else {
    Write-Host "Critical notes   : none" -ForegroundColor Green
}

Write-Host "==================================" -ForegroundColor Cyan
