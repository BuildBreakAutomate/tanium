<#
.SYNOPSIS
	Get-UptimeDetails reports reconciled endpoint uptime, boot type, and last cold boot as a Tanium sensor.
	# LICENSE #
	Copyright (C) 2026 - Brent Henderson - Build Break Automate LLC. - https://buildbreakautomate.com
	Need help with implementation? Contact me at https://buildbreakautomate.com/index.php/need-help/ for implementation / consulting services.
	Always happy to meet new people; add me on LinkedIn at https://www.linkedin.com/in/brentmhenderson/.
	This program is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published 
	by the Free Software Foundation, either version 3 of the License, or any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
	You should have received a copy of the GNU Lesser General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.
.DESCRIPTION
	Get-UptimeDetails determines endpoint uptime from up to three independent sources (Environment.TickCount64, PerfOS SystemUpTime, 
	and Win32_OperatingSystem.LastBootUpTime), selects the most reliable available source, and flags a clock anomaly when the sources disagree 
	beyond a set tolerance. It also identifies the current boot type (Cold, FastStartup, ResumeFromHibernate) and the last true cold boot 
	via Microsoft-Windows-Kernel-Boot event 27, since Fast Startup preserves the kernel session rather than performing a full restart, which can affect servicing and reboot compliance assessments.
.OUTPUTS
	A single row of 12 tilde-delimited (~) columns, no header:
	  1  UptimeSeconds       - Uptime in whole seconds from the selected source
	  2  UptimeDays          - Uptime in days, two decimal places (invariant culture)
	  3  UptimeBucket        - Sortable uptime range (e.g. '3: 7-14 Days')
	  4  BootTimeUTC         - Boot time derived from uptime, ISO 8601 UTC
	  5  BootTimeLocal       - Boot time derived from uptime, ISO 8601 local
	  6  BootType            - Cold, FastStartup, ResumeFromHibernate, or Unknown
	  7  LastColdBootUTC     - Most recent cold boot, ISO 8601 UTC
	  8  DaysSinceColdBoot   - Days since last cold boot, two decimal places
	  9  UptimeSource        - TickCount64, PerfOS_SystemUpTime, Win32_OperatingSystem, or Unavailable
	  10 SourceDeltaSeconds  - Widest disagreement between available sources, in seconds
	  11 ClockAnomaly        - True when SourceDeltaSeconds exceeds the skew tolerance (300s); Unknown with fewer than two sources
	  12 SensorVersion       - Sensor version string
	Columns with no determinable value return 'None'. A row is always returned, never [no results].
.NOTES
	Version  : 1.0.0
	Platform : Windows 10 / 11, Server 2016 / 2019 / 2022 / 2025
	Host     : PowerShell 5.1, 32-bit SYSTEM context (Tanium client default)
	All output is ASCII. Do not introduce non-ASCII characters; PS 5.1 will emit a BOM / mangled bytes through the Tanium pipe.
	No Sysnative calls required; every source is managed code or WMI, both of which are architecture-agnostic.
	TickCount64 requires .NET Framework 4.8 and is absent on unpatched Server 2016 builds; the sensor falls back to PerfOS, then WMI.
	If the Kernel-Boot event is unavailable, BootType falls back to the HiberbootEnabled policy value.
#>

##*=============================================
##* Begin: Variable Initialization
##*=============================================

## Variables: Preference settings

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

## Variables: Sensor constants

$SensorVersion = '1.0.0'
$D             = '~'
$NONE          = 'None'
$SKEW_TOLERANCE = 300   # Seconds of disagreement between sources before ClockAnomaly trips

##*=============================================
##* End: Variable Initialization
##*=============================================

##*=============================================
##* Begin: Function Declarations
##*=============================================

# Begin Region : Get-IsoUtc
function Get-IsoUtc {
     <#
.Synopsis
     Converts a datetime value to an ISO 8601 UTC string.
.Description
     Returns the value formatted as yyyy-MM-ddTHH:mm:ssZ in UTC. Returns 'None' if the input is not a datetime.
.Example
     PS C:\> Get-IsoUtc (Get-Date)
     2026-11-23T14:05:12Z
#>
    param($Value)
    if ($Value -is [datetime]) {
        return ([datetime]$Value).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    return $NONE
}
# End Region : Get-IsoUtc

# Begin Region : Get-IsoLocal
function Get-IsoLocal {
     <#
.Synopsis
     Converts a datetime value to an ISO 8601 local-time string.
.Description
     Returns the value formatted as yyyy-MM-ddTHH:mm:ss in the endpoint's local time zone. Returns 'None' if the input is not a datetime.
.Example
     PS C:\> Get-IsoLocal (Get-Date)
     2026-11-23T09:05:12
#>
    param($Value)
    if ($Value -is [datetime]) {
        return ([datetime]$Value).ToLocalTime().ToString('yyyy-MM-ddTHH:mm:ss')
    }
    return $NONE
}
# End Region : Get-IsoLocal

# Begin Region : Format-Decimal
function Format-Decimal {
     <#
.Synopsis
     Formats a number to two decimal places using the invariant culture.
.Description
     Forces invariant culture output. A machine set to de-DE would otherwise emit "12,34", and a long-running host would emit "1,234.56";
     both break the numeric column type in Tanium.
.Example
     PS C:\> Format-Decimal 12.3456
     12.35
#>
    param([double]$Value)
    return $Value.ToString('0.00', [System.Globalization.CultureInfo]::InvariantCulture)
}
# End Region : Format-Decimal

# Begin Region : Get-UptimeBucket
function Get-UptimeBucket {
     <#
.Synopsis
     Assigns an uptime value in days to a sortable range bucket.
.Description
     Returns a numbered bucket label so results sort in order in Tanium. Returns 'None' for negative values.
.Example
     PS C:\> Get-UptimeBucket -Days 9.5
     3: 7-14 Days
#>
    param([double]$Days)
    if ($Days -lt 0)   { return $NONE }
    if ($Days -lt 1)   { return '1: Under 1 Day' }
    if ($Days -lt 7)   { return '2: 1-7 Days' }
    if ($Days -lt 14)  { return '3: 7-14 Days' }
    if ($Days -lt 30)  { return '4: 14-30 Days' }
    if ($Days -lt 90)  { return '5: 30-90 Days' }
    return '6: Over 90 Days'
}
# End Region : Get-UptimeBucket

##*=============================================
##* End: Function Declarations
##*=============================================

##*=============================================
##* Begin: Uptime Source Collection
##*=============================================

# Source 1 : Environment.TickCount64
# Monotonic millisecond counter maintained by the kernel. Immune to wall-clock adjustment (NTP step, timezone, manual change).
# Added in .NET Framework 4.8, so it is absent on unpatched Server 2016 builds. The reflection guard avoids a hard property-not-found error on those hosts.

$tickUptime = $null
$tickProp = [System.Environment].GetProperty(
    'TickCount64',
    [System.Reflection.BindingFlags]'Public,Static'
)
if ($tickProp) {
    try {
        $ms = $tickProp.GetValue($null, $null)
        if ($null -ne $ms -and [double]$ms -gt 0) {
            $tickUptime = [math]::Floor([double]$ms / 1000)
        }
    } catch { $tickUptime = $null }
}

# Source 2 : PerfOS SystemUpTime
# Also tick-derived, reported in whole seconds. Present on every supported build.
# Requires a healthy WMI perf provider, so it is a secondary rather than primary source.

$perfUptime = $null
$perf = Get-CimInstance -ClassName Win32_PerfFormattedData_PerfOS_System -ErrorAction SilentlyContinue
if (-not $perf) {
    $perf = Get-WmiObject -Class Win32_PerfFormattedData_PerfOS_System -ErrorAction SilentlyContinue
}
if ($perf -and $null -ne $perf.SystemUpTime) {
    $candidate = [double]$perf.SystemUpTime
    if ($candidate -gt 0) { $perfUptime = [math]::Floor($candidate) }
}

# Source 3 : Win32_OperatingSystem.LastBootUpTime
# Wall-clock anchored boot timestamp. This is the value most tooling reports, and the one that drifts when the clock is stepped,
# when a VM is restored from snapshot, or after a live migration. Kept as the reconciliation reference, not the primary.

$now       = Get-Date
$wmiBoot   = $null
$wmiUptime = $null

$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if ($os -and $os.LastBootUpTime -is [datetime]) {
    $wmiBoot = [datetime]$os.LastBootUpTime
} else {
    $os2 = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os2 -and $os2.LastBootUpTime) {
        try { $wmiBoot = $os2.ConvertToDateTime($os2.LastBootUpTime) } catch { $wmiBoot = $null }
    }
}
if ($wmiBoot -is [datetime]) {
    $wmiUptime = [math]::Floor(($now - $wmiBoot).TotalSeconds)
}

##*=============================================
##* End: Uptime Source Collection
##*=============================================

##*=============================================
##* Begin: Uptime Source Reconciliation
##*=============================================

# Select the primary source in order of reliability: TickCount64, PerfOS, then WMI

$uptimeSeconds = $null
$uptimeSource  = $NONE

if ($null -ne $tickUptime) {
    $uptimeSeconds = $tickUptime
    $uptimeSource  = 'TickCount64'
} elseif ($null -ne $perfUptime) {
    $uptimeSeconds = $perfUptime
    $uptimeSource  = 'PerfOS_SystemUpTime'
} elseif ($null -ne $wmiUptime -and $wmiUptime -gt 0) {
    $uptimeSeconds = $wmiUptime
    $uptimeSource  = 'Win32_OperatingSystem'
}

# Calculate the widest disagreement between any two available sources

$sourceDelta  = $NONE
$clockAnomaly = $NONE
if ($null -ne $uptimeSeconds) {
    $values = @()
    foreach ($v in @($tickUptime, $perfUptime, $wmiUptime)) {
        if ($null -ne $v -and $v -gt 0) { $values += [double]$v }
    }
    if ($values.Count -ge 2) {
        $spread      = [math]::Round(($values | Measure-Object -Maximum).Maximum - ($values | Measure-Object -Minimum).Minimum, 0)
        $sourceDelta = [string][int]$spread
        if ($spread -gt $SKEW_TOLERANCE) { $clockAnomaly = 'True' } else { $clockAnomaly = 'False' }
    } else {
        $sourceDelta  = $NONE
        $clockAnomaly = 'Unknown'
    }
}

##*=============================================
##* End: Uptime Source Reconciliation
##*=============================================

##*=============================================
##* Begin: Boot Type / Cold Boot Detection
##*=============================================

# Fast Startup (hiberboot) resumes a hibernated kernel session instead of initialising a new one. Uptime resets, but drivers,
# kernel patches and pending servicing operations do NOT fully apply. A host can therefore show 8 hours of uptime and still be
# carrying a months-old kernel session.

# Microsoft-Windows-Kernel-Boot event 27, property 0:
#   0 = Cold boot   1 = Fast Startup (hiberboot)   2 = Resume from hibernate

$bootType       = 'Unknown'
$lastColdBoot   = $null
$daysSinceCold  = $NONE

$bootEvents = Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-Kernel-Boot'
    Id           = 27
} -MaxEvents 100 -ErrorAction SilentlyContinue

if ($bootEvents) {
    # Current boot type from the most recent event
    $current = $bootEvents | Select-Object -First 1
    if ($current -and $current.Properties.Count -ge 1) {
        switch ([int]$current.Properties[0].Value) {
            0 { $bootType = 'Cold' }
            1 { $bootType = 'FastStartup' }
            2 { $bootType = 'ResumeFromHibernate' }
            default { $bootType = 'Unknown' }
        }
    }

    # Most recent cold boot within the retrieved events
    foreach ($e in $bootEvents) {
        if ($e.Properties.Count -ge 1 -and [int]$e.Properties[0].Value -eq 0) {
            $lastColdBoot = $e.TimeCreated
            break
        }
    }
} else {
    # Event log unavailable or provider absent. Fall back to the policy state so the row still carries signal.
    $hb = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' `
                           -Name 'HiberbootEnabled' -ErrorAction SilentlyContinue
    if ($null -ne $hb -and $hb.HiberbootEnabled -eq 0) {
        # Fast Startup disabled by policy, so every boot is necessarily cold
        $bootType     = 'Cold'
        $lastColdBoot = $wmiBoot
    }
}

# Use the WMI boot time as the last cold boot if the current boot is cold but no cold boot event was found

if ($bootType -eq 'Cold' -and $null -eq $lastColdBoot -and $wmiBoot -is [datetime]) {
    $lastColdBoot = $wmiBoot
}

if ($lastColdBoot -is [datetime]) {
    $daysSinceCold = Format-Decimal ($now - $lastColdBoot).TotalDays
}

##*=============================================
##* End: Boot Type / Cold Boot Detection
##*=============================================

##*=============================================
##* Begin: Sensor Output
##*=============================================

# Never return an empty row. Tanium renders that as [no results] and the endpoint becomes indistinguishable from one that never answered.

if ($null -eq $uptimeSeconds) {
    $row = @($NONE, $NONE, $NONE, $NONE, $NONE, $bootType, (Get-IsoUtc $lastColdBoot),
             $daysSinceCold, 'Unavailable', $NONE, $NONE, $SensorVersion)
    Write-Output ($row -join $D)
    return
}

$uptimeDays = [math]::Round($uptimeSeconds / 86400, 2)
$bootTime   = $now.AddSeconds(-1 * $uptimeSeconds)

$row = @(
    [string][int64]$uptimeSeconds
    (Format-Decimal $uptimeDays)
    (Get-UptimeBucket -Days $uptimeDays)
    (Get-IsoUtc   $bootTime)
    (Get-IsoLocal $bootTime)
    $bootType
    (Get-IsoUtc $lastColdBoot)
    $daysSinceCold
    $uptimeSource
    $sourceDelta
    $clockAnomaly
    $SensorVersion
)

Write-Output ($row -join $D)

##*=============================================
##* End: Sensor Output
##*=============================================

# SIG # Begin signature block
# MIIrSgYJKoZIhvcNAQcCoIIrOzCCKzcCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALXtq4fO4TPdz5
# N+vXutcmwlJwaTYNsbiyfZh2mRwsBqCCEu4wggXdMIIDxaADAgECAgh7LJvTFoAy
# mTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMx
# EDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3JhdGlvbjExMC8G
# A1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0aG9yaXR5IFJTQTAe
# Fw0xNjAyMTIxNzM5MzlaFw00MTAyMTIxNzM5MzlaMHwxCzAJBgNVBAYTAlVTMQ4w
# DAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NMIENv
# cnBvcmF0aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlvbiBB
# dXRob3JpdHkgUlNBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA+Q/d
# oyt9y9Aq/uxnhabnLhu6d+Hj9a+k7PpKXZHEV0drGHdrdvL9k+Q9D8IWngtmw1aU
# nheDhc5W7/IW/QBi9SIJVOhlF05BueBPRpeqG8i4bmJeabFf2yoCfvxsyvNB2O3Q
# 6Pw/YUjtsAMUHRAOSxngu07shmX/NvNeZwILnYZVYf16OO3+4hkAt2+hUGJ1dDyg
# +sglkrRueiLH+B6h47LdkTGrKx0E/6VKBDfphaQzK/3i1lU0fBmkSmjHsqjTt8qh
# k4jrwZe8jPkd2SKEJHTHBD1qqSmTzOu4W+H+XyWqNFjIwSNUnRuYEcM4nH49hmyl
# D0CGfAL0XAJPKMuucZ8POsgz/hElNer8usVgPdl8GNWyqdN1eANyIso6wx/vLOUu
# qfqeLLZRRv2vA9bqYGjqhRY2a4XpHsCz3cQk3IAqgUFtlD7I4MmBQQCeXr9/xQiY
# ohgsQkCz+W84J0tOgPQ9gUfgiHzqHM61dVxRLhwrfxpyKOcAtdF0xtfkn60Hk7ZT
# NTX8N+TD9l0WviFz3pIK+KBjaryWkmo++LxlVZve9Q2JJgT8JRqmJWnLwm3KfOJZ
# X5es6+8uyLzXG1k8K8zyGciTaydjGc/86Sb4ynGbf5P+NGeETpnr/LN4CTNwumam
# du0bc+sapQ3EIhMglFYKTixsTrH9z5wJuqIz7YcCAwEAAaNjMGEwHQYDVR0OBBYE
# FN0ECQei9Xp9UlMSkpXuOIAlDaZZMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgw
# FoAU3QQJB6L1en1SUxKSle44gCUNplkwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3
# DQEBCwUAA4ICAQAgGBGUKfsmnRweHnBh8ZVyk3EkrWiTWI4yrxuzcAP8JSt0hZA9
# eGr0uYullzu1GJG7Hqf5QFuR+VWZrx4R0Fwdp2bjsZQHDDI5puobsHnYHZxwROOK
# 3cT5lR+KOEM/AYWlR6c9RrK85SJo93uc2Cw+CiHILTOsv8WBmTF0wXVxxb6x8CNF
# 9J1r/BljnaO8BMYYCyW7U4kPs4BQ3kXuRH+rlHhkmNP2KN2H2HBldPsOuRPrpw9h
# qTKWzN677WNMGLupQPegVG4giHF1GOp6tDRy4CMnd1y2kOqGJUCr7zMPy5+CvqIg
# +/a1LRrmwoWxdA/7yGUCpFIBR91JIsG/2OtrrH7e7GMzFbcjCI/GD41BWt2OxbmP
# 5UU/eNu60htAsf5xTT/ggaK6XrTsFeCT3QgffuFVmQsh3pOeCvvmo0m9NjD+53ey
# oHWXtS2BiBdlIPfakACfyVLMMso1fPU9D9gr1/UmbMkGNJYW6nBZGjJ5eQu2iH8P
# Ukg9v2zYokQu0U63cljTiROV/kSr+NeLG26cvCygW9VqAK9fN+HV+hALmJyG5yaP
# zvDsbopXC4DjTrLAoGNhkLpVaDd0araS25+hhiK2ZScO7LafQmDkZ8K12kELxNOL
# YRu8+h+RK9dEB166KazZxenvU0ha64DxKFghzbAGVfsnP1OQcKkEHlcnuTCCBnIw
# ggRaoAMCAQICCGQzUdPHOJ8IMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVT
# MQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UECgwPU1NM
# IENvcnBvcmF0aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlmaWNhdGlv
# biBBdXRob3JpdHkgUlNBMB4XDTE2MDYyNDIwNDQzMFoXDTMxMDYyNDIwNDQzMFow
# eDELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9u
# MREwDwYDVQQKDAhTU0wgQ29ycDE0MDIGA1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25p
# bmcgSW50ZXJtZWRpYXRlIENBIFJTQSBSMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAJ+DE3OqsMZtIcvbi3qHdNBx3I6Xcprku4g0tN2AA8YvRaR0mr8e
# D1Dqnm1485/6USapPZ3RspRXPvs5iRuRK1bvZ8vmC+MOOYzGNfSMPd0l6QGsF0J9
# WBZA3PnVKEQdlWQwYTpk8pfXc0x9eyMCbfN161U9b6otxK++dKxd/mq2/OpceekP
# Q5y1UgUP7z6xsY/QSa2m40IZVD/zLw6hy3z+E/kjOdolHLg+AEo6bzIwN2Qex651
# B9hV0hjJDoq8o1zwfAqnhYHCDq+PmVzTYCW8g1ppHCUTzXL165yAm9wsZ8TdyQmY
# 1XPrxCGj5TKOPi9SmMZgN2SMsm9KVHIYzCeH+s11omMhTLU9ZP0rpptVryZMYLS5
# XP6rQ72t0BNmUB8L0omm/9eABvHDEQIzM2EX91Yfji87aOcV8XdWSimeA9rCKyZh
# MlugVuVJKY02p/XHUqJWAyAvOHiAvfYGrkE0y5RFvZvHiRgfC7r/qa5qQJkT3e9Q
# 3wG68gTW0DHfNDheV1vIOB5W1KxIpu3/+bjBO+3CJL5EYKd3zdU9mFm0Q+qqYH3N
# wuUv8ev11CDVlzRuXQRrBRHS05KMCSdE7U81MUZ+dBkFYuyJ4+ojcJjk0S/UihMY
# RpNl5Vhz00w9J3oiP8P4o1W3+eaHguxFHsVuOnyxTrmraPebY9WRQbypAgMBAAGj
# gfswgfgwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTdBAkHovV6fVJTEpKV
# 7jiAJQ2mWTAwBggrBgEFBQcBAQQkMCIwIAYIKwYBBQUHMAGGFGh0dHA6Ly9vY3Nw
# cy5zc2wuY29tMBEGA1UdIAQKMAgwBgYEVR0gADATBgNVHSUEDDAKBggrBgEFBQcD
# AzA7BgNVHR8ENDAyMDCgLqAshipodHRwOi8vY3Jscy5zc2wuY29tL3NzbC5jb20t
# cnNhLVJvb3RDQS5jcmwwHQYDVR0OBBYEFFTC/hCVAJPNavXnwNfZsku4jwzjMA4G
# A1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEA9Q8mh3CvmaLK9dbJ8I1m
# PTmC04gj2IK/j1SEJ7bTgwfXnieJTYSOVNEg7mBD21dCPMewlfa+zOqjPY5PBsYr
# WYZ/63MbyuVAJuA9b8z2vXHGzX0OIEA51gXSr5QIv3/CUbcrtXuDIfBj2uWc4Wku
# dR1Oy2Ee9aUz3wKdFdntaZNXukZFLoC8Zb7nEj7eR/+QnBCt9laypNT61vwuvJch
# s3aD0pH6BlDRsYAogP7brQ9n7fh93NlwW3q6aLWzSmYXj+fw51fdaf68XuHVjJ8T
# u5WaFft5K4XVbT5nR24bB1z7VEUPFhEuEcOwvLVuHDNXlB7+QjRGjjFQTtszV5X6
# OOTmEturWC5Ft9kiyvRaR0ksKOhPjEI8ZGjp5kOsGZGpxxOCX/xxCje3nVB7PF33
# olKCNeS159MKb2v+jfmk19UdS+d9Ygj42desmUnbtYRBFC72LmCXU0ua/vGIenS6
# nnXp4NqnycwsO3tMCnjPlPc2YLaDPIpUy04NaCqUEXUmFOogN8zreRd2VXhxbeJJ
# ODM32+RsWccjYua8zi5US/1eAyrI3R5LcUTQdT4xYmWLKabtJOF6HYQ0f6QXfLSs
# fT81WMvDvxrdn1RWbUXlU/OIiisxo8o+UNEANOwnCMNnxlzoaL/PLhZluDxm/zuy
# lauajZ3MlPDteFB/7GRHo50wggaTMIIEe6ADAgECAhAT9ChHl7y3Divu0kiVDccj
# MA0GCSqGSIb3DQEBCwUAMHgxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQ
# MA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxNDAyBgNVBAMMK1NT
# TC5jb20gQ29kZSBTaWduaW5nIEludGVybWVkaWF0ZSBDQSBSU0EgUjEwHhcNMjYx
# MDI5MTQ1NjQyWhcNMjcxMDI5MTQ1NjQyWjB6MQswCQYDVQQGEwJVUzEQMA4GA1UE
# CAwHR2VvcmdpYTETMBEGA1UEBwwKU3RhdGVzYm9ybzEhMB8GA1UECgwYQnVpbGQg
# QnJlYWsgQXV0b21hdGUgTExDMSEwHwYDVQQDDBhCdWlsZCBCcmVhayBBdXRvbWF0
# ZSBMTEMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCcdsNyqvAPwN4s
# hL0BB5Cqhnfjq6owX67Q0eKQC207l2eXFd5ZhJrup0yu0DofSSzH6viqHkqXHxyq
# HX4esjrEf3YRsDlFyxsD7y5mT/qzABzY3TcBftZN50ge2YU43CVQzZh9VWY6QOp5
# IMtwh1dToo8OR2qY+upOgvtrSvSc8opOOUvnPLXhY9iDJYKkT2pxK/PNDr6XcTdu
# Sx61Xmfrx8f/UKqi/Pc08SiR2q5CpRPUaOozaqll8Q6Gnf0pcZ8+tWw9qTq+YwSf
# mWtI0omH8JgBp2rYE/6WFO86/1OglW5ofIKRDuO/u3UtWaf/J65v5RWNLrCQIXdE
# yoZkgrA5Jrx6MCNFNL2zWsh/anNvxzjBaYiJpT5+FUdn/lWS1KvcQP++FPmcZ7ju
# GtgPwjj48wEwXBz+HB+Ar7DFzJ5ZCHvBDm8Tpx7cfaRGsBe45239sF2Wkxq4w/ro
# dDMTnwVhwRypxBCGFdwgX1cVSuSCUUv2cD2T5+bsKDyx8+5JnNkCAwEAAaOCAZUw
# ggGRMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUVML+EJUAk81q9efA19myS7iP
# DOMwegYIKwYBBQUHAQEEbjBsMEgGCCsGAQUFBzAChjxodHRwOi8vY2VydC5zc2wu
# Y29tL1NTTGNvbS1TdWJDQS1Db2RlU2lnbmluZy1SU0EtNDA5Ni1SMS5jZXIwIAYI
# KwYBBQUHMAGGFGh0dHA6Ly9vY3Nwcy5zc2wuY29tMFEGA1UdIARKMEgwCAYGZ4EM
# AQQBMDwGDCsGAQQBgqkwAQMDATAsMCoGCCsGAQUFBwIBFh5odHRwczovL3d3dy5z
# c2wuY29tL3JlcG9zaXRvcnkwEwYDVR0lBAwwCgYIKwYBBQUHAwMwTQYDVR0fBEYw
# RDBCoECgPoY8aHR0cDovL2NybHMuc3NsLmNvbS9TU0xjb20tU3ViQ0EtQ29kZVNp
# Z25pbmctUlNBLTQwOTYtUjEuY3JsMB0GA1UdDgQWBBRIETUnM3jGAOw9mC7EHZDx
# Sm1rvzAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAANyUqcd4U61
# kSPTNpLJDGbvR5dd4tUdO+qItTjaIZ4A+HsfIK1d1dGydVWUQ1rrLSpP+hregeio
# VLR+jmP6B/+Xk8vZ47R8NtPy21Zy613NUuCJ+WBbrnBYmOyiUjYlOGfDoIR59rZo
# rhexIE67w+qr7PmhDCsdhCRxC4yhxcvQWFuxmNB6zBwgW5ThtOBFJnFMqXYwyQVA
# l40CHhn2rmjzWoSGQJ7lkXi2Ue0mdJKaJCi4UE4tSZTOzpqfu66ikMCaLOr/9ljI
# e+UFEKaFyDDqkZKPsxT9xBEPRW4gW9zCLsW29+/6FIgq61O+8fP0iz2WJblfKOJy
# t/H7kz4qz/E89v4ePdApi8D5LXeenU65G8tR0tXXAldXctbT7XVA1XlUGNvgxbVJ
# Mi7A/4zwGW+f1V6aToObxHZheY2RxroBiCXnAWWLDGo2/cCSRzNHdS9exJU0Nzw5
# ralkBiZBsysNsd3qN2qbo6y4rrUkRxTJxD0XDODeFp9KCojf5Wdw2GiXRdL5LHPM
# /3hxwoag+NopCG3Bc0laKNPPC/GrhazGsGCDyC0oGALjstCdzE4YGIKbH6lPOFhw
# wzqSwxap5yJzg1IeEzeO9D8qOfk9lYYJKpQIlZeD5eJ9RkNvMFihsX8dzXPWrO09
# Vo1fLeU+VZOKyjo4duiuFlqmaRhi5Pl2MYIXsjCCF64CAQEwgYwweDELMAkGA1UE
# BhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3VzdG9uMREwDwYDVQQK
# DAhTU0wgQ29ycDE0MDIGA1UEAwwrU1NMLmNvbSBDb2RlIFNpZ25pbmcgSW50ZXJt
# ZWRpYXRlIENBIFJTQSBSMQIQE/QoR5e8tw4r7tJIlQ3HIzANBglghkgBZQMEAgEF
# AKCBrzAUBgorBgEEAYI3AgEMMQYwBKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQB
# gjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLQYJKoZIhvcNAQk0
# MSAwHjANBglghkgBZQMEAgEFAKENBgkqhkiG9w0BAQsFADAvBgkqhkiG9w0BCQQx
# IgQg71t3k8F5fEK0zgTAX7MfMEU0/Ia7svNDBEPGZINYUgIwDQYJKoZIhvcNAQEL
# BQAEggGAYe52C5/qse3kSD7K09UEfNKILptRtDnXLATRfo0OGCfWi5TWA4KFiIDJ
# Mlpl/XMKxnKCHm7Fcd2EsVDoRt0n9tNNzPJ4CM0zANe83mHsEwVNsRJdT/d2Jbnz
# VFTwUqjWabEUWye/HvXwGk0wc+WsGhoiRYkS7Tf7pknZ4w+1EwkiNJ6umM8QJ1Fy
# g3SmI1wANI201sM8iARXUO7eVpJxKa71fVJrhEqi3/e0GJGJKhYxDv637q8hWdOT
# Y05R7zxn3y4nIpjek6taSqQy9lxKcacrtleauowYf8ZViAKprH3thS18uzrdlQ30
# lnAcS+kDcEPfLlf7v7fXvs1Qtktr3RlWMi+waoAMxI75ObwlyPTPGElAbz4CxvEY
# CIEsJZkqG/AQU2ttmelKRjJZODI4wy4Rjq1T+DriXahA4F6ktkCKugqqLygtyhmm
# 66djDC6W2qB+XatrcQnpPOEj6TeAyyuR/PsF8t58+aN2roOaV0rt8kTraguUpPRx
# mzigqDIUoYIUxDCCFMAGCisGAQQBgjcDAwExghSwMIIUrAYJKoZIhvcNAQcCoIIU
# nTCCFJkCAQMxDTALBglghkgBZQMEAgEwfwYLKoZIhvcNAQkQAQSgcARuMGwCAQEG
# DCsGAQQBgqkwAQMGATAxMA0GCWCGSAFlAwQCAQUABCC73QHv9Y+SkEkQhEOHF9JJ
# 4O9GOXTNnXhNf8lo3R8WWAIIRhkRZyPyWAYYDzIwMjYxMTIzMjIyMjQ1WjADAgEB
# AgYBogqBJTqgghGnMIIE8zCCAtugAwIBAgIQVEP4N71a7hgBhHK4XNqO4zANBgkq
# hkiG9w0BAQsFADByMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMxEDAOBgNV
# BAcMB0hvdXN0b24xETAPBgNVBAoMCFNTTCBDb3JwMS4wLAYDVQQDDCVTU0wuY29t
# IFRpbWVzdGFtcGluZyBJc3N1aW5nIFJTQSBDQSAyMB4XDTI2MDYxMjE3MjI0NloX
# DTM2MDYwOTE3MjI0NVowbjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAw
# DgYDVQQHDAdIb3VzdG9uMREwDwYDVQQKDAhTU0wgQ29ycDEqMCgGA1UEAwwhU1NM
# LmNvbSBUaW1lc3RhbXBpbmcgVW5pdCAyMDI2IEUxMFkwEwYHKoZIzj0CAQYIKoZI
# zj0DAQcDQgAE6CWLuGYTLkiSOPMLNskOBthXsIhRSA46feOQwvSLcDaNh6vxUzBK
# Ex1KdFBRFs7OHrnH/K0VA6MbDQIFpUg0PaOCAVIwggFOMB8GA1UdIwQYMBaAFHCa
# ZcFDgKP86bFkiW7xMJwJIcl8ME0GCCsGAQUFBwEBBEEwPzA9BggrBgEFBQcwAoYx
# aHR0cDovL2NlcnQuc3NsLmNvbS9TU0wuY29tLXRpbWVTdGFtcGluZy1JLVIyLmNl
# cjBRBgNVHSAESjBIMDwGDCsGAQQBgqkwAQMGATAsMCoGCCsGAQUFBwIBFh5odHRw
# czovL3d3dy5zc2wuY29tL3JlcG9zaXRvcnkwCAYGZ4EMAQQCMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmxzLnNzbC5j
# b20vU1NMLmNvbS10aW1lU3RhbXBpbmctSS1SMi5jcmwwHQYDVR0OBBYEFCesA1a6
# KGq6FzuDPUB/eagk7MM8MA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOC
# AgEAT3ZuzvwDnsIZTXBn+hjmuBXgzB12fbYxT9uYe6ZvhvpbZWKcyDQgacETkPw8
# k6yeqnYCYyFZ063lMPEqAhAD2nMG614Zh7PtHW9DWqfsgivxbPYBeN+t7UxgkYT3
# expbWMdPEqBtWVyHOvLcKvMxgJWfJjANwVkwVDfky/j7cf28+iimN8PKc7S/u8/L
# enRRnV2W2YfncRnkz9Cfs5nRDzaZguiHrrp2GxwgnNQSH4GBjHOl3PzLsnVbGoZK
# i4ZEjgXups4mGGOK7+GB2HAlQn+OS944cHqlkH0gElt2WezoCNRpELph9qaxuBnj
# SEqXWWfgE6yGBwO0uxKNqpWVTHmAwr6SvBPofxubXIuEn9ivR4CLOuAxUSrJ41ZB
# g/qqG0oJjF6GkRKbxq7cyWSkEZYJhmKCg2Hg5fXHagOxiwbmn5JPZ1vhWCrbk3v/
# dTx2gvTK5+erC5H9/rTcljUI776yd2rfhjfkpvyAsbtXs4D7nrnw8i9wor5+fdtR
# SJBVxqzLmykFftoL0Up2Q++tyKCUdribdcnrB4HKS3s+t3AjdcbA06DCL8GifQi9
# fL0yRBRNlA4o6BP+Sr755MaCNjURYZDvDyxJHBBT7cqjZIwsiR8s+6860noFbBBt
# dge2Iw7CPC/1Q31I27hVolS7B0yao3v8X2MtWy3msZlXTcEwggXdMIIDxaADAgEC
# Agh7LJvTFoAymTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzEOMAwGA1UE
# CAwFVGV4YXMxEDAOBgNVBAcMB0hvdXN0b24xGDAWBgNVBAoMD1NTTCBDb3Jwb3Jh
# dGlvbjExMC8GA1UEAwwoU1NMLmNvbSBSb290IENlcnRpZmljYXRpb24gQXV0aG9y
# aXR5IFJTQTAeFw0xNjAyMTIxNzM5MzlaFw00MTAyMTIxNzM5MzlaMHwxCzAJBgNV
# BAYTAlVTMQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjEYMBYGA1UE
# CgwPU1NMIENvcnBvcmF0aW9uMTEwLwYDVQQDDChTU0wuY29tIFJvb3QgQ2VydGlm
# aWNhdGlvbiBBdXRob3JpdHkgUlNBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA+Q/doyt9y9Aq/uxnhabnLhu6d+Hj9a+k7PpKXZHEV0drGHdrdvL9k+Q9
# D8IWngtmw1aUnheDhc5W7/IW/QBi9SIJVOhlF05BueBPRpeqG8i4bmJeabFf2yoC
# fvxsyvNB2O3Q6Pw/YUjtsAMUHRAOSxngu07shmX/NvNeZwILnYZVYf16OO3+4hkA
# t2+hUGJ1dDyg+sglkrRueiLH+B6h47LdkTGrKx0E/6VKBDfphaQzK/3i1lU0fBmk
# SmjHsqjTt8qhk4jrwZe8jPkd2SKEJHTHBD1qqSmTzOu4W+H+XyWqNFjIwSNUnRuY
# EcM4nH49hmylD0CGfAL0XAJPKMuucZ8POsgz/hElNer8usVgPdl8GNWyqdN1eANy
# Iso6wx/vLOUuqfqeLLZRRv2vA9bqYGjqhRY2a4XpHsCz3cQk3IAqgUFtlD7I4MmB
# QQCeXr9/xQiYohgsQkCz+W84J0tOgPQ9gUfgiHzqHM61dVxRLhwrfxpyKOcAtdF0
# xtfkn60Hk7ZTNTX8N+TD9l0WviFz3pIK+KBjaryWkmo++LxlVZve9Q2JJgT8JRqm
# JWnLwm3KfOJZX5es6+8uyLzXG1k8K8zyGciTaydjGc/86Sb4ynGbf5P+NGeETpnr
# /LN4CTNwumamdu0bc+sapQ3EIhMglFYKTixsTrH9z5wJuqIz7YcCAwEAAaNjMGEw
# HQYDVR0OBBYEFN0ECQei9Xp9UlMSkpXuOIAlDaZZMA8GA1UdEwEB/wQFMAMBAf8w
# HwYDVR0jBBgwFoAU3QQJB6L1en1SUxKSle44gCUNplkwDgYDVR0PAQH/BAQDAgGG
# MA0GCSqGSIb3DQEBCwUAA4ICAQAgGBGUKfsmnRweHnBh8ZVyk3EkrWiTWI4yrxuz
# cAP8JSt0hZA9eGr0uYullzu1GJG7Hqf5QFuR+VWZrx4R0Fwdp2bjsZQHDDI5puob
# sHnYHZxwROOK3cT5lR+KOEM/AYWlR6c9RrK85SJo93uc2Cw+CiHILTOsv8WBmTF0
# wXVxxb6x8CNF9J1r/BljnaO8BMYYCyW7U4kPs4BQ3kXuRH+rlHhkmNP2KN2H2HBl
# dPsOuRPrpw9hqTKWzN677WNMGLupQPegVG4giHF1GOp6tDRy4CMnd1y2kOqGJUCr
# 7zMPy5+CvqIg+/a1LRrmwoWxdA/7yGUCpFIBR91JIsG/2OtrrH7e7GMzFbcjCI/G
# D41BWt2OxbmP5UU/eNu60htAsf5xTT/ggaK6XrTsFeCT3QgffuFVmQsh3pOeCvvm
# o0m9NjD+53eyoHWXtS2BiBdlIPfakACfyVLMMso1fPU9D9gr1/UmbMkGNJYW6nBZ
# GjJ5eQu2iH8PUkg9v2zYokQu0U63cljTiROV/kSr+NeLG26cvCygW9VqAK9fN+HV
# +hALmJyG5yaPzvDsbopXC4DjTrLAoGNhkLpVaDd0araS25+hhiK2ZScO7LafQmDk
# Z8K12kELxNOLYRu8+h+RK9dEB166KazZxenvU0ha64DxKFghzbAGVfsnP1OQcKkE
# HlcnuTCCBsswggSzoAMCAQICEFKdu8K4iYf1g4DgsOuiBjYwDQYJKoZIhvcNAQEL
# BQAwfDELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVRleGFzMRAwDgYDVQQHDAdIb3Vz
# dG9uMRgwFgYDVQQKDA9TU0wgQ29ycG9yYXRpb24xMTAvBgNVBAMMKFNTTC5jb20g
# Um9vdCBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSBSU0EwHhcNMjYwNjEyMTY0MjE1
# WhcNNDEwMjEyMTczOTM5WjByMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFVGV4YXMx
# EDAOBgNVBAcMB0hvdXN0b24xETAPBgNVBAoMCFNTTCBDb3JwMS4wLAYDVQQDDCVT
# U0wuY29tIFRpbWVzdGFtcGluZyBJc3N1aW5nIFJTQSBDQSAyMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAny+r5nNNkLwxRps2B3laUGNU9y7vWiJ5013y
# f0iXz65bQdwa9bjj8l/SkeXqHGqfSh2Foae+80E8mDEf93oIwjsy2CX2cXmKxqtF
# 8HJGYB4f6yRhKED50wkbOysL02IXf+/EZna44jffhhVz4OU/k52xQ/PnIg/uFhc2
# Wk+Sc/CHqAr+lYVkPz7Ly5RqB9f1RKGr9JC37W1LgVdHC50dNIdsa3QXPhltYZub
# R3npE4Bbfi0joUW5n5O0ayweN45R/YVLxA0YGlp1OHVfVnsqXq8bhnw1Lc4kjJ6X
# OgXlOlw/a8ze57TvbduZl3ehewTmvO0Aky/nqOWDS9IPPxdxdG6vprBbSuHlxNAN
# BAbHTiFgkfZmf0dZYlT/AnZIoFxAq0HILPolf4OgWgET76SiWSlm2XYRIXwVjpeq
# G0plvXwRIQBzSiEJj7QeQFnCvHx4gQMINvN3+yG/1rxhEbajGve0tTP3lX4PPOHV
# AE0QJp4ZzPI1YYJkhVRriVVxVRU4Fsg4BPwP6I+YLmHb1tZ4RLwOFNLh/gJYDgPl
# ChCoxOogFxXgwPZZrDyERYB0aeOexW0OKacN4RRu9cqF2KKu/Ab5AL7eYDLVGUPr
# EEyYbIMApVKqpebc0/jDQniC+3rkauRAjgVc8m1ip/CQgG1Dw4Z9ulVRAY9VR6Za
# 26LsTbUCAwEAAaOCAVEwggFNMBIGA1UdEwEB/wQIMAYBAf8CAQAwHwYDVR0jBBgw
# FoAU3QQJB6L1en1SUxKSle44gCUNplkwTQYIKwYBBQUHAQEEQTA/MD0GCCsGAQUF
# BzAChjFodHRwOi8vY2VydC5zc2wuY29tL1NTTGNvbS1Sb290Q0EtUlNBLTQwOTYt
# UjEuY2VyMD8GA1UdIAQ4MDYwNAYEVR0gADAsMCoGCCsGAQUFBwIBFh5odHRwczov
# L3d3dy5zc2wuY29tL3JlcG9zaXRvcnkwEwYDVR0lBAwwCgYIKwYBBQUHAwgwQgYD
# VR0fBDswOTA3oDWgM4YxaHR0cDovL2NybHMuc3NsLmNvbS9TU0xjb20tUm9vdENB
# LVJTQS00MDk2LVIxLmNybDAdBgNVHQ4EFgQUcJplwUOAo/zpsWSJbvEwnAkhyXww
# DgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBCwUAA4ICAQBlFFvNMemA6iBiBYo5
# 6IKQjWhWuQaYKuo4qpf0KJNERAt1gz+HsA2SL3xA/V+EA8SRPNP9SvX0is+5mDsp
# pYvpKyYGqYP36YFW0mbF1F0ZtXxumCUUO/ZV5mBNKDf5Q4PY7Qb0eWAepUc0rNJr
# /Mvn5ZiXfJPxDb2xmcg8aRD652/nr+Ork2UBP0E43iJdI4LF7Vs29R3SGRLYZOxM
# 15DI4QebsKRl0KDlf4OmYGCKc7umTxibkZtN1C1KWgnf9jadU/JwnySaYEBgx6/v
# +FVC6SGONziY7TcvI9MV+qYxHUPlOm6AaQP2dS4bjWXnm86ldCbUkxtOACumSfT9
# 7077JNiVa7PZ1IBkd/2PE1AC8gs7U+/Yk1BN9XRPIi15k/uA1xF9oeee5KGjyiGK
# kqIT7W8QkgUT5zeCinFKkcKafZMcROSVYpXtmtQqGGR2g4uPYqJ0K1hms6gJXrHt
# /34p8M9PrV8oNWe0Zl1ErDMtXndUg3qhJL4pA3ZUlo7w5lM5ml+A7ijr/3Gk2v4Q
# RoDeE2ShmTXdHgtqo8L/fT119mYcETycE2NYGRXsBl3N0rzDsHRr8P3TrprqhRrX
# 04iS0P7eQ+lDxgS3yhGn3OzWGhDt9Gf2x1qe0/qdhFAVOkXxzMZz4Uat6xsAfzX0
# +/m8GEKW5Ojw/HY+kLvVwzSPOzGCAlcwggJTAgEBMIGGMHIxCzAJBgNVBAYTAlVT
# MQ4wDAYDVQQIDAVUZXhhczEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NM
# IENvcnAxLjAsBgNVBAMMJVNTTC5jb20gVGltZXN0YW1waW5nIElzc3VpbmcgUlNB
# IENBIDICEFRD+De9Wu4YAYRyuFzajuMwCwYJYIZIAWUDBAIBoIIBYDAaBgkqhkiG
# 9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MTEyMzIyMjI0
# NVowKAYJKoZIhvcNAQk0MRswGTALBglghkgBZQMEAgGhCgYIKoZIzj0EAwIwLwYJ
# KoZIhvcNAQkEMSIEII1ItInt7Ft7q6KLFxMNatL3ckc+ad8rDHqDLvqNrcN1MIHI
# BgsqhkiG9w0BCRACLzGBuDCBtTCBsjCBrwQgV0/qF6r6XnxqK5sIyZixc15FCzhz
# ykTmokygkw5j87AwgYowdqR0MHIxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVUZXhh
# czEQMA4GA1UEBwwHSG91c3RvbjERMA8GA1UECgwIU1NMIENvcnAxLjAsBgNVBAMM
# JVNTTC5jb20gVGltZXN0YW1waW5nIElzc3VpbmcgUlNBIENBIDICEFRD+De9Wu4Y
# AYRyuFzajuMwCgYIKoZIzj0EAwIESDBGAiEAjRSzH2NsERVjdcILmbOwQquraNvL
# KeEHXuj+U4nxoP8CIQCFLgV2vkfoDWhLyCwLvGL7v2NxZCwLYNIbKty2rlf8cg==
# SIG # End signature block
