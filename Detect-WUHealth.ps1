<#
    Detect-WUHealth.ps1  (v2)
    Intune Remediations - detectiescript

    Instellingen in Intune:
      - Run this script using the logged-on credentials : No  (draait als SYSTEM)
      - Run script in 64-bit PowerShell                 : Yes

    Controleert (trigger voor remediation):
      1. Uitgeschakelde update-/telemetrieservices
      2. WSUS/GPO-restanten die Windows Update blokkeren (incl. AUOptions=1)
         (WSUS-checks worden overgeslagen als de ConfigMgr-client aanwezig is)
         en AllowAutoUpdate=5 via Intune (automatische updates uit)
      3. Pauze door de gebruiker
      4. Windows-versie end of service
      5. Laatste cumulatieve update (LCU) ouder dan $MaxDaysSinceLCU dagen

    Alleen info (geen trigger): reboot pending / installatie bezig, pauze of
    versiepin via Intune, telemetrie uit, vrije schijfruimte, laatste scan.

    Exit 1 = probleem gevonden -> remediation draait
    Exit 0 = OK
#>

$MaxDaysSinceLCU = 45   # gelijk houden met het remediationscript
$EosWarnDays     = 60   # waarschuwen als end of service binnen zoveel dagen valt

$issues = New-Object System.Collections.Generic.List[string]
$info   = New-Object System.Collections.Generic.List[string]

#region Gedeelde functies (identiek in detectie- en remediationscript)

function Get-LastLCUDate {
    # Primair: CBS-registratie van de LCU zelf (blijft bewaard na reset van SoftwareDistribution)
    $pkgRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
    $dates = @(Get-ChildItem -Path $pkgRoot -ErrorAction SilentlyContinue |
        Where-Object { $_.PSChildName -like 'Package_for_RollupFix*' } |
        ForEach-Object {
            $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
            # CurrentState 112 = Installed
            if ($p.CurrentState -eq 112 -and $null -ne $p.InstallTimeHigh -and $null -ne $p.InstallTimeLow) {
                try {
                    # Werkt ongeacht of Windows de DWORD als Int32 (negatief) of UInt32/Int64 teruggeeft
                    $low  = [int64]$p.InstallTimeLow
                    if ($low -lt 0) { $low += 4294967296 }
                    $high = [int64]$p.InstallTimeHigh
                    [datetime]::FromFileTime(($high * 4294967296) + $low)
                } catch { }
            }
        })
    if ($dates.Count -gt 0) { return ($dates | Sort-Object -Descending | Select-Object -First 1) }

    # Fallback: Windows Update-historie, alleen Windows-LCU's (geen Office/.NET/Defender)
    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            $hist = @($searcher.QueryHistory(0, [Math]::Min($count, 300)) | Where-Object {
                $_.Operation -eq 1 -and $_.ResultCode -in 2, 3 -and
                $_.Title -notmatch '\.NET' -and
                ($_.Title -match '(Cumulative Update|Cumulatieve update).*Windows' -or
                 $_.Title -match '(Security Update|Beveiligingsupdate) \(KB\d+\) \(\d{5}\.\d+\)')
            } | ForEach-Object { $_.Date.ToLocalTime() })
            if ($hist.Count -gt 0) { return ($hist | Sort-Object -Descending | Select-Object -First 1) }
        }
    } catch { }
    return $null
}

function Get-UpdateBusyReason {
    # Geeft een reden terug als er een reboot openstaat of een installatie loopt, anders $null
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    foreach ($k in $keys) { if (Test-Path $k) { return 'reboot pending' } }
    try { if ((New-Object -ComObject Microsoft.Update.Installer).IsBusy) { return 'installatie bezig' } } catch { }
    if (Get-Process -Name TiWorker -ErrorAction SilentlyContinue) { return 'TiWorker actief' }
    return $null
}

function Get-OSInfo {
    $cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

    # End of service per Windows 11-build: Home/Pro, Enterprise/Education
    $eosTable = @{
        '22000' = @('2023-10-10', '2024-10-08')   # 21H2
        '22621' = @('2024-10-08', '2025-10-14')   # 22H2
        '22631' = @('2025-11-11', '2026-11-10')   # 23H2
        '26100' = @('2026-10-13', '2027-10-12')   # 24H2
        '26200' = @('2027-10-12', '2028-10-10')   # 25H2
    }

    $edition = [string]$cv.EditionID
    $class = 'Pro'
    if     ($edition -match '^(IoT)?EnterpriseSN?$')                           { $class = 'LTSC' }
    elseif ($edition -match '^(Enterprise|Education|IoTEnterprise|ServerRdsh)N?$') { $class = 'Enterprise' }

    $eos = $null
    $build = [string]$cv.CurrentBuild
    if ($class -ne 'LTSC' -and $eosTable.ContainsKey($build)) {
        $idx = 0
        if ($class -eq 'Enterprise') { $idx = 1 }
        $eos = [datetime]::ParseExact($eosTable[$build][$idx], 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
    }

    [pscustomobject]@{
        Build        = "$($cv.CurrentBuild).$($cv.UBR)"
        CurrentBuild = $build
        Version      = [string]$cv.DisplayVersion
        Edition      = $edition
        EndOfService = $eos
    }
}

#endregion

$os     = Get-OSInfo
$coMgmt = [bool](Get-Service -Name CcmExec -ErrorAction SilentlyContinue)

# --- 1. Uitgeschakelde services ---
foreach ($name in 'wuauserv', 'UsoSvc', 'BITS', 'CryptSvc', 'DiagTrack') {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartType -eq 'Disabled') { $issues.Add("Service $name disabled") }
}

# --- 2. WSUS/GPO-restanten ---
$wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$wu = Get-ItemProperty -Path $wuKey -ErrorAction SilentlyContinue
$au = Get-ItemProperty -Path "$wuKey\AU" -ErrorAction SilentlyContinue

if ($coMgmt) {
    $info.Add('ConfigMgr-client aanwezig: WSUS-checks overgeslagen')
} else {
    if ($wu.WUServer)                                           { $issues.Add("WSUS-server ingesteld: $($wu.WUServer)") }
    if ($au.UseWUServer -eq 1)                                  { $issues.Add('UseWUServer=1') }
    if ($wu.DoNotConnectToWindowsUpdateInternetLocations -eq 1) { $issues.Add('DoNotConnectToWindowsUpdateInternetLocations=1') }
    foreach ($n in 'SetPolicyDrivenUpdateSourceForQualityUpdates', 'SetPolicyDrivenUpdateSourceForFeatureUpdates') {
        if ($wu.$n -eq 1) { $issues.Add("$n=1 (WSUS als bron)") }
    }
    # AUOptions=1 = automatische updates uit: de Update Orchestrator zoekt dan nooit naar Windows-updates
    if ($au.AUOptions -eq 1) { $issues.Add('AUOptions=1 via GPO/register (automatische updates uit)') }
    $auLocal = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -ErrorAction SilentlyContinue
    if ($auLocal.AUOptions -eq 1) { $issues.Add('AUOptions=1 in Auto Update-sleutel (automatische updates uit)') }
}
if ($wu.DisableWindowsUpdateAccess -eq 1) { $issues.Add('DisableWindowsUpdateAccess=1') }
if ($au.NoAutoUpdate -eq 1)               { $issues.Add('NoAutoUpdate=1') }

# AllowAutoUpdate via Intune: 5 = automatische updates uit (probleem).
# 6 = 'Reset to default': Intune dwingt niets af en Windows valt terug op lokale AUOptions (alleen info).
$pmUpd = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -ErrorAction SilentlyContinue
if ($pmUpd.AllowAutoUpdate -eq 5) {
    $issues.Add('AllowAutoUpdate=5 via Intune (automatische updates uit) - update ring aanpassen')
} elseif ($pmUpd.AllowAutoUpdate -eq 6) {
    $info.Add('AllowAutoUpdate=6 (Reset to default): lokale AUOptions bepaalt gedrag')
}
if ($wu.TargetReleaseVersion -eq 1 -and $wu.TargetReleaseVersionInfo -and $os.Version -and
    ([string]$wu.TargetReleaseVersionInfo -le $os.Version)) {
    $issues.Add("Versie vastgezet via GPO/register op $($wu.ProductVersion) $($wu.TargetReleaseVersionInfo)")
}
if ($wu.SetDisableUXWUAccess -eq 1) { $info.Add('SetDisableUXWUAccess=1 (gebruiker kan WU niet bedienen)') }

# --- 3. Pauze door gebruiker ---
$ux = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction SilentlyContinue
$pausedUntil = $null
foreach ($n in 'PauseUpdatesExpiryTime', 'PauseQualityUpdatesEndTime', 'PauseFeatureUpdatesEndTime') {
    if ($ux.$n) {
        try { if ([datetime]$ux.$n -gt (Get-Date)) { $pausedUntil = $ux.$n } } catch { }
    }
}
if ($pausedUntil) { $issues.Add("Gepauzeerd door gebruiker tot $pausedUntil") }

# --- 4. End of service ---
if ($os.EndOfService) {
    $days = [int]($os.EndOfService - (Get-Date).Date).TotalDays
    if ($days -lt 0) {
        $issues.Add("Windows $($os.Version) $($os.Edition) is end of service sinds $($os.EndOfService.ToString('yyyy-MM-dd')) - feature update nodig")
    } elseif ($days -le $EosWarnDays) {
        $info.Add("LET OP: $($os.Version) $($os.Edition) end of service over $days dagen")
    }
}
if ($os.CurrentBuild -eq '19045') { $info.Add('Windows 10 22H2: updates alleen met ESU') }

# --- 5. Leeftijd laatste cumulatieve update ---
$last = Get-LastLCUDate
if ($last) {
    $age = [int]((Get-Date) - $last).TotalDays
    $info.Add("laatste CU $age dagen ($($last.ToString('yyyy-MM-dd')))")
    if ($age -gt $MaxDaysSinceLCU) { $issues.Add("Laatste cumulatieve update is $age dagen oud") }
} else {
    $issues.Add('Geen geinstalleerde cumulatieve update gevonden')
}

# --- Info (geen trigger) ---
$busy = Get-UpdateBusyReason
if ($busy) { $info.Add($busy) }

$pm = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -ErrorAction SilentlyContinue
if ($pm.PauseQualityUpdates -eq 1)  { $info.Add('quality updates gepauzeerd via Intune') }
if ($pm.PauseFeatureUpdates -eq 1)  { $info.Add('feature updates gepauzeerd via Intune') }
if ($pm.TargetReleaseVersion)       { $info.Add("Intune versiepin: $($pm.ProductVersion) $($pm.TargetReleaseVersion)") }

$dc = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -ErrorAction SilentlyContinue
if ($dc.AllowTelemetry -eq 0) { $info.Add('LET OP: AllowTelemetry=0 via policy') }

try {
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'" -ErrorAction Stop
    $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
    if ($freeGB -lt 15) { $info.Add("LET OP: $freeGB GB vrij") } else { $info.Add("$freeGB GB vrij") }
} catch { }

try {
    $ls = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate
    if ($ls -and $ls.Year -gt 2000) { $info.Add("laatste geslaagde scan $($ls.ToString('yyyy-MM-dd'))") }
} catch { }

try { if ((Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).PartOfDomain) { $info.Add('domain joined') } } catch { }

# --- Output ---
$head = "Build $($os.Build) ($($os.Version), $($os.Edition))"
if ($issues.Count -gt 0) { $out = "NOK | $head | " + ($issues -join '; ') } else { $out = "OK | $head" }
if ($info.Count -gt 0)   { $out += ' | ' + ($info -join '; ') }
if ($out.Length -gt 2000) { $out = $out.Substring(0, 2000) }
Write-Output $out

if ($issues.Count -gt 0) { exit 1 }
exit 0