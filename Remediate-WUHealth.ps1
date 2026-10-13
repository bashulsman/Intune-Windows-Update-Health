<#
    Remediate-WUHealth.ps1  (v2)
    Intune Remediations - remediationscript

    Instellingen in Intune:
      - Run this script using the logged-on credentials : No  (draait als SYSTEM)
      - Run script in 64-bit PowerShell                 : Yes

    Herstelt Windows Update:
      1. Uitgeschakelde services terug naar Windows-standaard
      2. WSUS/GPO-restanten verwijderen (WSUS-deel overgeslagen bij ConfigMgr-client)
         incl. AUOptions=1; AllowAutoUpdate=5 via Intune wordt alleen gemeld
      3. Pauze door gebruiker opheffen
      4. Update-services herstarten als er beleid is gewijzigd
      5. Als de laatste CU te oud is: Windows Update-componenten resetten
         (SoftwareDistribution + catroot2), NIET als:
           - er een reboot openstaat of een installatie loopt
           - de Windows-versie end of service is (reset helpt dan niet)
           - de vorige reset minder dan $MinDaysBetweenResets dagen geleden was
      6. Scan starten

    Log: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WUHealth-Remediation.log
    (wordt meegenomen door 'Collect diagnostics')

    Let op: Intune draait na de remediation direct opnieuw de detectie. Zolang er nog
    geen nieuwe CU is geinstalleerd en het device niet herstart is, blijft de status
    'Recurred'. Dat is verwacht gedrag.
#>

$MaxDaysSinceLCU      = 45   # gelijk houden met het detectiescript
$MinDaysBetweenResets = 7

$LogFile  = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs\WUHealth-Remediation.log'
$StateKey = 'HKLM:\SOFTWARE\WUHealthRemediation'
$actions  = New-Object System.Collections.Generic.List[string]

function Write-Log([string]$Message) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    try { Add-Content -Path $LogFile -Value $line -ErrorAction Stop } catch { }
}

function Remove-RegValue([string]$Path, [string]$Name) {
    $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $p) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        Write-Log "Registerwaarde verwijderd: $Path\$Name (was: $($p.$Name))"
        return $true
    }
    return $false
}

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

# --- Log roteren (max ~1 MB) ---
try {
    if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 1MB)) {
        Move-Item -Path $LogFile -Destination "$LogFile.old" -Force -ErrorAction Stop
    }
} catch { }

$os        = Get-OSInfo
$busy      = Get-UpdateBusyReason
$coMgmt    = [bool](Get-Service -Name CcmExec -ErrorAction SilentlyContinue)
$restartWU = $false

Write-Log '=== Start remediation ==='
Write-Log "Build $($os.Build) ($($os.Version), $($os.Edition)) | ConfigMgr: $coMgmt | Bezig: $(if ($busy) { $busy } else { 'nee' })"

# --- 1. Services terug naar standaard (alleen als ze Disabled staan) ---
$defaults = [ordered]@{
    wuauserv  = 'demand'
    BITS      = 'demand'
    CryptSvc  = 'auto'
    UsoSvc    = 'delayed-auto'
    DiagTrack = 'auto'
}
foreach ($name in $defaults.Keys) {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc -and $svc.StartType -eq 'Disabled') {
        & sc.exe config $name 'start=' $defaults[$name] | Out-Null
        $actions.Add("$name -> $($defaults[$name])")
        Write-Log "Service $name ingesteld op $($defaults[$name])"
        $restartWU = $true
    }
}

# --- 2. WSUS/GPO-restanten verwijderen ---
$wuKey   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$auKey   = "$wuKey\AU"
$removed = New-Object System.Collections.Generic.List[string]

$wuNames = @('DisableWindowsUpdateAccess')
$auNames = @('NoAutoUpdate')
if ($coMgmt) {
    Write-Log 'ConfigMgr-client aanwezig: WSUS-instellingen niet aangepast'
} else {
    $wuNames += 'WUServer', 'WUStatusServer', 'UpdateServiceUrlAlternate',
                'DoNotConnectToWindowsUpdateInternetLocations', 'DisableDualScan',
                'SetPolicyDrivenUpdateSourceForQualityUpdates', 'SetPolicyDrivenUpdateSourceForFeatureUpdates',
                'SetPolicyDrivenUpdateSourceForDriverUpdates', 'SetPolicyDrivenUpdateSourceForOtherUpdates',
                'TargetGroup', 'TargetGroupEnabled'
    $auNames += 'UseWUServer'
}

# Versiepin via GPO/register alleen weghalen als die op of onder de huidige versie staat
$wu = Get-ItemProperty -Path $wuKey -ErrorAction SilentlyContinue
if ($wu.TargetReleaseVersion -eq 1 -and $wu.TargetReleaseVersionInfo -and $os.Version -and
    ([string]$wu.TargetReleaseVersionInfo -le $os.Version)) {
    $wuNames += 'TargetReleaseVersion', 'TargetReleaseVersionInfo', 'ProductVersion'
}

foreach ($n in $wuNames) { if (Remove-RegValue -Path $wuKey -Name $n) { $removed.Add($n) } }
foreach ($n in $auNames) { if (Remove-RegValue -Path $auKey -Name $n) { $removed.Add($n) } }

# AUOptions=1 (automatische updates uit) weghalen; andere AUOptions-waarden blijven staan
if (-not $coMgmt) {
    $auLocalKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
    foreach ($k in $auKey, $auLocalKey) {
        $v = (Get-ItemProperty -Path $k -Name AUOptions -ErrorAction SilentlyContinue).AUOptions
        if ($v -eq 1 -and (Remove-RegValue -Path $k -Name 'AUOptions')) { $removed.Add("AUOptions ($(Split-Path $k -Leaf))") }
    }
}

# AllowAutoUpdate via Intune kan lokaal niet blijvend worden aangepast: alleen melden
$pmUpd = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update' -ErrorAction SilentlyContinue
if ($pmUpd.AllowAutoUpdate -eq 5) {
    $actions.Add('LET OP: AllowAutoUpdate=5 via Intune, update ring aanpassen (Automatic update behavior)')
    Write-Log 'AllowAutoUpdate=5 via Intune: automatische updates staan uit, aanpassen in de update ring'
}

if ($removed.Count -gt 0) {
    $actions.Add('verwijderd: ' + ($removed -join ', '))
    $restartWU = $true
    try {
        if ((Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).PartOfDomain) {
            $actions.Add('LET OP: domain joined, GPO kan waarden terugzetten')
            Write-Log 'Device is domain joined: controleer of een GPO deze waarden opnieuw zet'
        }
    } catch { }
}

# --- 3. Pauze door gebruiker opheffen ---
$uxKey = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
$ux = Get-ItemProperty -Path $uxKey -ErrorAction SilentlyContinue
$paused = $false
foreach ($n in 'PauseUpdatesExpiryTime', 'PauseQualityUpdatesEndTime', 'PauseFeatureUpdatesEndTime') {
    if ($ux.$n) {
        try { if ([datetime]$ux.$n -gt (Get-Date)) { $paused = $true } } catch { }
    }
}
if ($paused) {
    foreach ($n in 'PauseUpdatesExpiryTime', 'PauseUpdatesStartTime',
                   'PauseQualityUpdatesStartTime', 'PauseQualityUpdatesEndTime',
                   'PauseFeatureUpdatesStartTime', 'PauseFeatureUpdatesEndTime') {
        Remove-ItemProperty -Path $uxKey -Name $n -ErrorAction SilentlyContinue
    }
    $upKey = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings'
    if (Test-Path $upKey) {
        foreach ($n in 'PausedQualityDate', 'PausedFeatureDate') {
            Remove-ItemProperty -Path $upKey -Name $n -ErrorAction SilentlyContinue
        }
        foreach ($n in 'PausedQualityStatus', 'PausedFeatureStatus') {
            if ($null -ne (Get-ItemProperty -Path $upKey -Name $n -ErrorAction SilentlyContinue)) {
                Set-ItemProperty -Path $upKey -Name $n -Value 0 -ErrorAction SilentlyContinue
            }
        }
    }
    $actions.Add('pauze opgeheven')
    Write-Log 'Pauze van Windows Update opgeheven'
    $restartWU = $true
}

# --- 4. Services herstarten zodat gewijzigd beleid wordt ingelezen ---
if ($restartWU) {
    if ($busy) {
        $actions.Add("herstart WU-services uitgesteld ($busy)")
        Write-Log "Herstart WU-services overgeslagen: $busy"
    } else {
        foreach ($s in 'wuauserv', 'UsoSvc') { Restart-Service -Name $s -Force -ErrorAction SilentlyContinue }
        Write-Log 'wuauserv en UsoSvc herstart'
    }
}

# --- 5. Componenten resetten als de laatste CU te oud is ---
$last  = Get-LastLCUDate
$age   = $null
if ($last) { $age = [int]((Get-Date) - $last).TotalDays }
$stale = (-not $last) -or ($age -gt $MaxDaysSinceLCU)
$eosPassed = [bool]($os.EndOfService -and ((Get-Date).Date -gt $os.EndOfService))

$lastReset = $null
try { $lastReset = [datetime](Get-ItemProperty -Path $StateKey -Name LastReset -ErrorAction Stop).LastReset } catch { }
$recentReset = [bool]($lastReset -and (((Get-Date) - $lastReset).TotalDays -lt $MinDaysBetweenResets))

if ($last) { Write-Log "Laatste CU: $($last.ToString('yyyy-MM-dd')) ($age dagen)" } else { Write-Log 'Laatste CU: niet gevonden' }

if (-not $stale) {
    Write-Log 'CU is actueel genoeg, geen reset nodig'
}
elseif ($eosPassed) {
    $actions.Add("geen reset: Windows $($os.Version) $($os.Edition) is end of service, feature update via Intune nodig")
    Write-Log "Reset overgeslagen: versie end of service sinds $($os.EndOfService.ToString('yyyy-MM-dd'))"
}
elseif ($busy) {
    $actions.Add("reset overgeslagen: $busy")
    Write-Log "Reset overgeslagen: $busy"
}
elseif ($recentReset) {
    $actions.Add("reset overgeslagen: laatste reset $($lastReset.ToString('yyyy-MM-dd'))")
    Write-Log "Reset overgeslagen, laatste reset: $lastReset"
}
else {
    Write-Log 'Reset Windows Update-componenten'
    $stamp = Get-Date -Format 'yyyyMMddHHmm'
    $svcs  = 'UsoSvc', 'wuauserv', 'BITS', 'CryptSvc'

    foreach ($folder in "$env:windir\SoftwareDistribution", "$env:windir\System32\catroot2") {
        $parent = Split-Path $folder -Parent
        $leaf   = Split-Path $folder -Leaf

        # Oude backups van eerdere resets opruimen
        Get-ChildItem -Path $parent -Directory -Filter "$leaf.bak*" -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

        if (-not (Test-Path $folder)) { continue }
        $bakName = "$leaf.bak_$stamp"

        $done = $false
        for ($i = 1; $i -le 3 -and -not $done; $i++) {
            foreach ($s in $svcs) { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Seconds 5
            try {
                Rename-Item -Path $folder -NewName $bakName -ErrorAction Stop
                $done = $true
                $actions.Add("$leaf gereset")
                Write-Log "$folder hernoemd naar $bakName"
            } catch {
                Write-Log "Poging $i hernoemen $folder mislukt: $($_.Exception.Message)"
            }
        }
        if (-not $done) { $actions.Add("$leaf reset mislukt") }
    }

    foreach ($s in 'CryptSvc', 'BITS', 'wuauserv', 'UsoSvc') { Start-Service -Name $s -ErrorAction SilentlyContinue }

    if (-not (Test-Path $StateKey)) { New-Item -Path $StateKey -Force | Out-Null }
    Set-ItemProperty -Path $StateKey -Name LastReset -Value (Get-Date).ToString('o')
}

# --- 6. Scan starten ---
if ($busy) {
    Write-Log "Scan overgeslagen: $busy"
} else {
    try {
        Start-Process -FilePath "$env:windir\System32\UsoClient.exe" -ArgumentList 'StartScan' -WindowStyle Hidden -ErrorAction Stop
        $actions.Add('scan gestart')
        Write-Log 'UsoClient StartScan gestart'
    } catch {
        Write-Log "Scan starten mislukt: $($_.Exception.Message)"
    }
}

if ($actions.Count -eq 0) { $actions.Add('geen acties nodig') }
Write-Log ('Klaar: ' + ($actions -join '; '))
Write-Output ("Build $($os.Build) ($($os.Version)) | " + ($actions -join '; '))
exit 0