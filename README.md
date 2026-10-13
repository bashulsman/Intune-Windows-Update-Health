# Windows Update Health – Intune Remediation

A detection and remediation script pair for **Microsoft Intune Remediations** that finds and fixes the common reasons Windows Update stops working on managed Windows 10/11 devices.

| File | Purpose |
|---|---|
| `Detect-WUHealth.ps1` | Checks the device and reports one line of status. Exit `1` when an issue is found. |
| `Remediate-WUHealth.ps1` | Repairs what it safely can, logs every action and starts a new scan. |

## Why

A device that quietly stops patching often looks fine in Intune: it is compliant, checks in daily and still gets Defender and Store updates. Meanwhile it can be months behind on cumulative updates and never get a feature update.

A real example that led to these scripts: an Intune update ring with **Automatic update behavior = Reset to default** sends `AllowAutoUpdate=6`, which means Intune enforces nothing and Windows falls back to local settings. On one device, an old local `AUOptions=1` (automatic updates off) was still present. The Update Orchestrator therefore never scanned for Windows updates, and the device sat on the same build for nine months, while other devices with the same ring were fine.

## What it checks

### Triggers remediation

| Check | Details |
|---|---|
| Disabled services | `wuauserv`, `UsoSvc`, `BITS`, `CryptSvc`, `DiagTrack` set to *Disabled* |
| WSUS leftovers | `WUServer`, `UseWUServer`, `DoNotConnectToWindowsUpdateInternetLocations`, `SetPolicyDrivenUpdateSourceFor*` (skipped when the ConfigMgr client is present) |
| Automatic updates off | `AUOptions=1` in `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` or `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update`; `NoAutoUpdate=1`; `AllowAutoUpdate=5` via Intune |
| Windows Update blocked | `DisableWindowsUpdateAccess=1` |
| Version pin via GPO/registry | `TargetReleaseVersionInfo` at or below the current version |
| Paused by user | Active pause in `WindowsUpdate\UX\Settings` |
| End of service | Windows 11 version past end of service for its edition (Home/Pro vs. Enterprise/Education; LTSC excluded) |
| Outdated | Latest cumulative update older than `$MaxDaysSinceLCU` days (default 45) |

The age of the latest cumulative update is read from the CBS package registration (`Package_for_RollupFix`), so it survives a SoftwareDistribution reset and is not confused by Office, .NET or Defender updates. The Windows Update history is used as a fallback.

### Info only

The following is added to the output but does not trigger remediation:

- reboot pending or installation in progress
- `AllowAutoUpdate=6` (Reset to default)
- pause or version pin via Intune
- `SetDisableUXWUAccess=1`
- `AllowTelemetry=0`
- end of service within 60 days, and Windows 10 22H2 (ESU only)
- free disk space, last successful scan, domain joined

## What it fixes

1. **Services** – disabled services are set back to their Windows defaults.
2. **Policy leftovers** – removes the WSUS/GPO values above, including `AUOptions=1`. Other `AUOptions` values are left alone. WSUS-related values are left untouched when the ConfigMgr client (`CcmExec`) is present.
3. **User pause** – lifts a pause set by the user.
4. **Service restart** – restarts `wuauserv` and `UsoSvc` after a policy change, so the change is picked up.
5. **Component reset** – renames `SoftwareDistribution` and `catroot2` when the latest CU is too old. The reset is skipped when:
   - a reboot is pending or an installation is running (a reset would break it)
   - the Windows version is past end of service (a reset won't help, a feature update is needed)
   - the previous reset was less than `$MinDaysBetweenResets` days ago (default 7)
6. **Scan** – starts a scan with `UsoClient StartScan`.

The script does **not** change Intune-managed settings. `AllowAutoUpdate=5` is only reported, because it has to be fixed in the update ring.

## Intune setup

**Devices → Scripts and remediations → Create**

| Setting | Value |
|---|---|
| Detection script | `Detect-WUHealth.ps1` |
| Remediation script | `Remediate-WUHealth.ps1` |
| Run this script using the logged-on credentials | **No** |
| Enforce script signature check | No (or sign the scripts) |
| Run script in 64-bit PowerShell | **Yes** – otherwise registry reads are redirected to `WOW6432Node` |

**Schedule:** daily is enough for normal use. Hourly is fine temporarily while you troubleshoot a device.

**Requirements:** Windows 10/11, Windows PowerShell 5.1, and licensing that includes Intune Remediations (for example Windows Enterprise E3/E5 or Microsoft 365 Business Premium).

## Reading the results

In **Device status**, add these columns via **Columns**:

- *Pre-remediation detection output*
- *Remediation output*
- *Post-remediation detection output*
- *Remediation error*

Example detection output:

```
NOK | Build 26100.7462 (24H2, Enterprise) | AUOptions=1 via GPO/registry (automatic updates off); Latest cumulative update is 270 days old | AllowAutoUpdate=6 (Reset to default): local AUOptions determines behavior; last CU 270 days (2026-01-16); 307.6 GB free; last successful scan 2026-10-13
```

Example remediation output:

```
Build 26100.7462 (24H2) | removed: AUOptions (AU), AUOptions (Auto Update); scan started
```

**"Recurred" is expected at first.** Intune runs the detection again right after the remediation. The CU stays "too old" until the new update is installed and the device has restarted, so a fixed device usually shows *Recurred* for a few days before it turns to *Without issues*.

## Logging

The remediation script writes to:

```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WUHealth-Remediation.log
```

- The file is included in Intune **Collect diagnostics**.
- It rotates at about 1 MB (`.old`).
- Every removed registry value is logged with its old value, so you can see when a value keeps coming back.
- The detection script does not write a log; its output is visible in Intune.

Intune only shows the latest run per device, so use this log for history.

The date of the last component reset is stored in `HKLM\SOFTWARE\WUHealthRemediation\LastReset`.

## Configuration

Both scripts have their settings at the top:

| Variable | Default | Script | Meaning |
|---|---|---|---|
| `$MaxDaysSinceLCU` | `45` | both (keep in sync) | Maximum age of the latest cumulative update |
| `$EosWarnDays` | `60` | detection | Warn this many days before end of service |
| `$MinDaysBetweenResets` | `7` | remediation | Minimum days between component resets |

The end-of-service table in `Get-OSInfo` must be updated when a new Windows version is released. The functions in the `Shared functions` region are identical in both scripts, so change them in both.

## Notes

- Tested on Windows 11 24H2 and 25H2 (Enterprise).
- The Windows Update history fallback matches English and Dutch update titles; add patterns for other languages if needed.
- On domain-joined devices a GPO may set removed values again. The remediation output then shows a warning.
- Test on a small pilot group before assigning broadly.

## Disclaimer

Provided as-is, without warranty. Review and test in your own environment before production use.
