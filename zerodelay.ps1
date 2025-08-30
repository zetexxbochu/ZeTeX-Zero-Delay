<#
    ZeTeX Zero Delay Utility - Full
    - Zero Delay core tweaks
    - GUS COMP TIER (Fortnite GameUserSettings.ini performance profile)
    - Aim Tweaks (safe input improvements only)
    - FPS Boost ++ (startup/service/cleanup/power/visual tweaks)
    - Automatic backups and a revert script
    Author: ZeTeX (2025)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param()

function Log {
    param([string]$s, [ConsoleColor]$c = 'Cyan')
    Write-Host $s -ForegroundColor $c
}

# Ensure admin
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This script must be run as Administrator. Restart PowerShell as Admin and run again."
    exit 1
}

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$backupRoot = "$env:ProgramData\ZeTeX_ZeroDelay\backup_$ts"
New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null
Log "Backup folder: $backupRoot" Green

# ---------- Helpers ----------
function Export-RegistryKeySafe {
    param($hkPath, $outFile)
    try {
        reg export $hkPath $outFile /y > $null 2>&1
        if (Test-Path $outFile) { Log "Exported $hkPath -> $outFile" Green }
    } catch {
        Log "Failed exporting $hkPath: $_" Yellow
    }
}

function Set-RegistryDword {
    param($path, $name, [int]$value)
    try {
        # backup single key (parent)
        $safeFile = Join-Path $backupRoot ("reg_" -f 0)  # placeholder
        # Use New-ItemProperty / Set-ItemProperty
        New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $path -Name $name -Value $value -Force
        Log "Set $path\$name = $value"
    } catch {
        Log "Failed to set $path\$name : $_" Yellow
    }
}

function Set-RegistryString {
    param($path, $name, $value)
    try {
        New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $path -Name $name -Value $value -Force
        Log "Set $path\$name = $value"
    } catch {
        Log "Failed to set $path\$name : $_" Yellow
    }
}

function Backup-File {
    param($file)
    if (Test-Path $file) {
        $dest = Join-Path $backupRoot (Split-Path $file -Leaf)
        Copy-Item -Path $file -Destination $dest -Force
        Log "Backed up $file -> $dest"
    }
}

# ---------- 1) Core Zero Delay tweaks ----------
Log "`n== ZERO DELAY: Core system tweaks ==" Magenta

try {
    # Timer resolution - we'll call timeBeginPeriod via a tiny background process
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class T {
  [DllImport("winmm.dll", EntryPoint="timeBeginPeriod")] public static extern uint tbp(uint m);
  [DllImport("winmm.dll", EntryPoint="timeEndPeriod")] public static extern uint tep(uint m);
}
"@ -ErrorAction SilentlyContinue

    # request 1 ms (kept while script runs — longer effect requires an app to hold it)
    [T]::tbp(1) | Out-Null
    Log "Requested 1ms timer resolution (active while session continues)." Green
} catch {
    Log "Timer resolution request failed or unsupported on this system." Yellow
}

# Power plan: Ultimate Performance (create/activate)
try {
    $uid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" > $null 2>&1
    powercfg -duplicatescheme $uid > $null 2>&1
    powercfg -setactive $uid
    Log "Activated Ultimate Performance power plan (if available)." Green
} catch {
    Log "Power plan change failed: $_" Yellow
}

# HDD/USB selective suspend disable (on current scheme)
try {
    powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_USB 29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA 0 > $null 2>&1
    powercfg /SETDCVALUEINDEX SCHEME_CURRENT SUB_USB 29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA 0 > $null 2>&1
    powercfg /SETACTIVE SCHEME_CURRENT > $null 2>&1
    Log "Disabled USB selective suspend for current power scheme." Green
} catch {
    Log "USB selective suspend tweak failed." Yellow
}

# MMCSS / SystemResponsiveness & NetworkThrottling
try {
    $mmRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    Export-RegistryKeySafe "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" (Join-Path $backupRoot "SystemProfile.reg")
    Set-ItemProperty -Path $mmRoot -Name "SystemResponsiveness" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $mmRoot -Name "NetworkThrottlingIndex" -Value 0xFFFFFFFF -Type DWord -Force
    Log "Set SystemResponsiveness=0 and NetworkThrottlingIndex=0xFFFFFFFF" Green
} catch {
    Log "Failed MMCSS tweaks: $_" Yellow
}

# Game scheduler (Tasks\Games)
try {
    $gamesKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    Export-RegistryKeySafe "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" (Join-Path $backupRoot "Tasks_Games.reg")
    New-Item -Path $gamesKey -Force | Out-Null
    Set-ItemProperty -Path $gamesKey -Name "GPU Priority" -Value 8 -Force
    Set-ItemProperty -Path $gamesKey -Name "Priority" -Value 6 -Force
    Set-ItemProperty -Path $gamesKey -Name "Scheduling Category" -Value "High" -Force
    Set-ItemProperty -Path $gamesKey -Name "SFIO Priority" -Value "High" -Force
    Log "Applied Game scheduling optimizations." Green
} catch {
    Log "Failed to optimize Tasks\Games: $_" Yellow
}

# Disable Game DVR & Game Bar (current user)
try {
    Export-RegistryKeySafe "HKCU:\System\GameConfigStore" (Join-Path $backupRoot "HKCU_GameConfigStore.reg")
    Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "ShowStartupPanel" -Value 0 -Force
    Log "Disabled Game DVR & Game Bar for current user." Green
} catch {
    Log "Failed to disable Game DVR/Game Bar." Yellow
}

# ---------- 2) GUS COMP TIER (Fortnite: GameUserSettings.ini) ----------
Log "`n== GUS COMP TIER: Fortnite performance profile ==" Magenta

# Possible Fortnite locations (Epic/Steam)
$gusPaths = @(
    "$env:LOCALAPPDATA\FortniteGame\Saved\Config\WindowsClient\GameUserSettings.ini",
    "$env:USERPROFILE\Saved Games\FortniteGame\Saved\Config\WindowsClient\GameUserSettings.ini"
)

$found = $false
foreach ($p in $gusPaths) {
    if (Test-Path $p) {
        $found = $true
        Backup-File $p
        $content = Get-Content $p -Raw

        # Replace or add common settings for FPS/performance and bloom reduction
        # Note: Fortnite keys can vary between versions. We perform safe pattern edits and add values if missing.
        $replacements = @{
            "sg.ResolutionQuality" = "50.000000"            # render scale
            "sg.ViewDistanceQuality" = "0"
            "sg.AntiAliasingQuality" = "0"
            "sg.ShadowQuality" = "0"
            "sg.PostProcessQuality" = "0"
            "sg.TextureQuality" = "0"
            "sg.EffectsQuality" = "0"
            "sg.FoliageQuality" = "0"
            "sg.MotionBlurQuality" = "0"
            "bUseDynamicResolution" = "False"
            "bMotionBlur" = "False"
            # Bloom reducer attempt (many games use PostProcess settings)
            "r.DefaultFeature.Bloom" = "0"
            # Lower screen percentage and sharpen
            "sg.ResampleQuality" = "0"
        }

        foreach ($k in $replacements.Keys) {
            $val = $replacements[$k]
            if ($content -match "(?m)^\s*$k\s*=") {
                $content = $content -replace "(?m)^(\s*$k\s*=).*", "`$1 $val"
            } else {
                # add to end
                $content += "`r`n$k=$val"
            }
        }

        # Save edited file (backup already made)
        $outPath = $p
        Set-Content -Path $outPath -Value $content -Force -Encoding UTF8
        Log "Patched $outPath with GUS COMP TIER performance values." Green
    }
}

if (-not $found) { Log "No Fortnite GameUserSettings.ini found in common locations. If you use Epic, ensure the game has been launched once." Yellow }

# ---------- 3) Aim Tweaks (safe) ----------
Log "`n== AIM TWEAKS: safe input tweaks ==" Magenta

try {
    # Turn off Enhance pointer precision
    $mouseReg = "HKCU:\Control Panel\Mouse"
    Export-RegistryKeySafe "HKCU\Control Panel\Mouse" (Join-Path $backupRoot "Mouse.reg")
    Set-ItemProperty -Path $mouseReg -Name "MouseSensitivity" -Value "10" -Force
    Set-ItemProperty -Path $mouseReg -Name "SmoothMouseXCurve" -Value 0 -Force
    Set-ItemProperty -Path $mouseReg -Name "SmoothMouseYCurve" -Value 0 -Force
    Set-ItemProperty -Path $mouseReg -Name "MouseSpeed" -Value 0 -Force
    Set-ItemProperty -Path $mouseReg -Name "MouseThreshold1" -Value 0 -Force
    Set-ItemProperty -Path $mouseReg -Name "MouseThreshold2" -Value 0 -Force
    # Enhance pointer precision (0 = off)
    Set-ItemProperty -Path $mouseReg -Name "MouseAcceleration" -Value 0 -Force -ErrorAction SilentlyContinue
    # Windows raw input preference for many games is automatic; ensure foreground lock timeout is small
    $kbdReg = "HKCU:\Control Panel\Desktop"
    Export-RegistryKeySafe "HKCU\Control Panel\Desktop" (Join-Path $backupRoot "Desktop.reg")
    Set-ItemProperty -Path $kbdReg -Name "ForegroundLockTimeout" -Value 0 -Force
    Log "Applied safe input tweaks (pointer precision off, foreground unlock)." Green
} catch {
    Log "Failed to apply some aim/input tweaks: $_" Yellow
}

# Note: Mouse polling is controlled by hardware/driver; do not change via registry here.

# ---------- 4) FPS Boost ++ ----------
Log "`n== FPS BOOST ++: system cleanup & startup tweaks ==" Magenta

# 4.1 Clear temp files (user & system)
try {
    $tempPaths = @("$env:TEMP", "$env:WINDIR\Temp")
    foreach ($tp in $tempPaths) {
        try { Get-ChildItem -Path $tp -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue } catch {}
        Log "Cleared $tp (best-effort)." Green
    }
} catch {
    Log "Temp cleanup failed: $_" Yellow
}

# 4.2 Clear Windows Update cache (SoftwareDistribution) safe approach
try {
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    $sd = "$env:SystemRoot\SoftwareDistribution"
    if (Test-Path $sd) {
        Backup-File "$sd"
        Get-ChildItem -Path $sd -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
        Log "Cleared Windows Update cache (SoftwareDistribution) - service stopped and folder cleaned (best-effort)." Green
    }
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
} catch {
    Log "Windows Update cache cleanup partially failed: $_" Yellow
}

# 4.3 Trim SSD (if SSD)
try {
    Get-PhysicalDisk | Where-Object MediaType -eq 'SSD' -ErrorAction SilentlyContinue | ForEach-Object {
        Log "Sending optimize/trim to SSD volumes..." Green
        Optimize-Volume -DriveLetter C -ReTrim -Verbose -ErrorAction SilentlyContinue | Out-Null
    }
} catch {
    # Try optimize all volumes
    try { Get-Volume | ForEach-Object { Optimize-Volume -DriveLetter $_.DriveLetter -ReTrim -ErrorAction SilentlyContinue } } catch {}
    Log "Volume trim attempted (best-effort)." Green
}

# 4.4 Visual Effects -> Adjust for best performance
try {
    $perfReg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    # We will set system performance options via registry "PerformanceOptions" is tricky; simpler: use rundll to set
    rundll32.exe shell32.dll,Options_RunDLL 0 > $null 2>&1
    # fallback: set specific keys to reduce animations (best-effort)
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" -Force
    Log "Applied visual tweaks to reduce animations (best-effort)." Green
} catch {
    Log "Visual tweaks failed: $_" Yellow
}

# 4.5 Disable common unnecessary startup apps (user-level) - best-effort
try {
    $startEntries = Get-CimInstance -ClassName Win32_StartupCommand -ErrorAction SilentlyContinue | Where-Object { $_.User -eq $env:USERNAME -or $_.User -eq $null } 
    foreach ($e in $startEntries) {
        # we do not blindly remove. Instead, for known safe entries, we remove; others we leave.
        $name = $e.Command
        if ($name -match "OneDrive|Spotify|EpicGamesLauncher|Discord|GeForceExperience|Steam") {
            try {
                # Attempt to disable by removing registry run entries matching this path (best-effort)
                $cmd = [Regex]::Escape($e.Command)
                # search run keys
                foreach ($rk in "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run") {
                    Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue | ForEach-Object {
                        $_.PSObject.Properties | Where-Object { $_.Name -ne "PSPath" } | ForEach-Object {
                            if ($_.Value -and $_.Value -match [Regex]::Escape($e.Command)) {
                                Remove-ItemProperty -Path $rk -Name $_.Name -ErrorAction SilentlyContinue
                                Log "Removed startup registry entry $($_.Name) from $rk" Green
                            }
                        }
                    }
                }
            } catch {}
        }
    }
    Log "Attempted to remove common heavyweight startup apps (OneDrive/Discord/GeForce/Steam/Epic/Spotify) from Run keys (user-level)." Green
} catch {
    Log "Startup cleanup partial failure." Yellow
}

# 4.6 Disable unnecessary telemetry & non-critical services (safer subset)
try {
    $svcList = @(
        "DiagTrack"          # Connected User Experiences and Telemetry (if present)
        ,"dmwappushservice"   # Device Management Wireless
        ,"WMPNetworkSvc"      # Windows Media Player Network Sharing Service
    )
    foreach ($s in $svcList) {
        if (Get-Service -Name $s -ErrorAction SilentlyContinue) {
            try {
                Set-Service -Name $s -StartupType Disabled -ErrorAction SilentlyContinue
                Stop-Service -Name $s -Force -ErrorAction SilentlyContinue
                Log "Disabled service: $s" Green
            } catch {
                Log "Could not disable $s (may be protected): $_" Yellow
            }
        }
    }
} catch {
    Log "Service disable step failed (partial)." Yellow
}

# 4.7 CPU priority: set game process priority when launching (advice)
Log "Tip: For specific games, prefer to start the game and set process Priority=High in Task Manager (or use a lightweight launcher)." Cyan

# ---------- 5) Create revert script ----------
Log "`n== CREATING REVERT SCRIPT ==" Magenta

$revertPath = Join-Path $backupRoot "zerodelay-revert.ps1"
$revertContent = @"
<#
    Revert script for ZeTeX Zero Delay changes
    - Restores backed up files and registry exports (best-effort)
#>

param()

Write-Host 'Reverting ZeTeX Zero Delay changes...' -ForegroundColor Cyan

\$backupRoot = '$backupRoot'

# Restore files (GameUserSettings, SoftwareDistribution backup if present)
Get-ChildItem -Path \$backupRoot -Filter '*.ini','*GameUserSettings*','SoftwareDistribution*' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        if (\$_.Extension -eq '.ini' -or \$_.Name -match 'GameUserSettings') {
            \$dest = Join-Path (Split-Path \$_.FullName -Parent) \$_.Name
            Copy-Item -Path \$_.FullName -Destination \$_.FullName -Force -ErrorAction SilentlyContinue
        }
    } catch {}
}

# Import any reg files exported by this utility
Get-ChildItem -Path \$backupRoot -Filter '*.reg' -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        reg import `"\$($_.FullName)`" | Out-Null
        Write-Host "Imported registry backup: \$($_.FullName)" -ForegroundColor Green
    } catch {
        Write-Host "Failed to import \$($_.FullName): \$_" -ForegroundColor Yellow
    }
}

Write-Host 'Revert attempt complete. Some changes (like services) may require a manual review or reboot.' -ForegroundColor Cyan
"@

Set-Content -Path $revertPath -Value $revertContent -Force -Encoding UTF8
Log "Created revert script: $revertPath" Green
Log "To revert: run PowerShell as Admin and execute:`n`n`"powershell -ExecutionPolicy Bypass -File `"$revertPath`"`n" Cyan

# ---------- 6) Final notes ----------
Log "`n== DONE ==" Magenta
Log "Backup saved at: $backupRoot" Green
Log "Reboot recommended to apply all changes fully." Yellow
Log "Script finished. Use the revert script if you want to attempt to roll back backed-up settings." Cyan

# Keep timer resolution until user closes PS session: end note
Log "Note: The 1ms timer request is held for the session that ran this script. To release it, restart your PC or call timeEndPeriod if implemented in a persistent app." Yellow
