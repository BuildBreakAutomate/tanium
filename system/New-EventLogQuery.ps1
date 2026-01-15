<#
.SYNOPSIS
    Tanium sensor for querying Windows Event Logs with flexible filtering.

.DESCRIPTION
    Retrieves events from specified Windows Event Logs based on provider, event IDs,
    and time range. Resolves user SIDs to account names using multiple fallback methods.

.PARAMETER Days
    Number of days to look back (default: 7)

.PARAMETER ID
    Comma-separated list of Event IDs to filter

.PARAMETER LogName
    Event Log name (e.g., System, Application, Setup, Microsoft-Windows-WindowsUpdateClient/Operational)

.PARAMETER ProviderName
    Event provider/source name (e.g., Microsoft-Windows-WindowsUpdateClient)

.EXAMPLE
    Feature Update Events (Setup progress):
        Days: 30
        ID: 4, 1, 2
        LogName: Microsoft-Windows-Setup
        ProviderName: Microsoft-Windows-Setup

.EXAMPLE
    Windows Update Client Events (Download/Install):
        Days: 7
        ID: 19, 20, 25, 31, 41, 44
        LogName: System
        ProviderName: Microsoft-Windows-WindowsUpdateClient

.EXAMPLE
    Feature Update Detailed Progress (SetupHost):
        Days: 30
        ID: 1, 4, 5, 6, 7, 8, 9, 10
        LogName: Microsoft-Windows-Upgrade-Diagnostic-App/Operational
        ProviderName: Microsoft-Windows-Upgrade-Diagnostics

.NOTES
    Output format: TimeCreated~EventID~OpCode~Message~Account~SID
    Returns "No matching events detected" if no events found.
    Returns error details if query fails.
.AUTHOR
    Brent M. Henderson - Build Break Automate LLC
	Copyright (c) 2025 - Build Break Automate LLC. - https://buildbreakautomate.com
	Need help with implementation? Contact me at https://buildbreakautomate.com/index.php/need-help/ for implementation / consulting services.
	Always happy to meet new people; add me on LinkedIn at https://www.linkedin.com/in/brentmhenderson/.
.LICENSE
    MIT License

    Copyright (c) 2026 Build Break Automate LLC

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
#>

# Tanium parameter ingestion with defaults
$Days = [System.Uri]::UnescapeDataString("||Days||")
$ID = [System.Uri]::UnescapeDataString("||ID||")
$LogName = [System.Uri]::UnescapeDataString("||LogName||")
$ProviderName = [System.Uri]::UnescapeDataString("||ProviderName||")

# Parameter validation and defaults
if ([string]::IsNullOrWhiteSpace($Days) -or $Days -match '^\|\|') { $Days = 7 }
if ([string]::IsNullOrWhiteSpace($LogName) -or $LogName -match '^\|\|') { 
    return "Error: LogName parameter is required"
}
if ([string]::IsNullOrWhiteSpace($ProviderName) -or $ProviderName -match '^\|\|') {
    return "Error: ProviderName parameter is required"
}
if ([string]::IsNullOrWhiteSpace($ID) -or $ID -match '^\|\|') {
    return "Error: ID parameter is required"
}

# Parse parameters
try {
    $DaysInt = [int]$Days
    $IDArray = $ID -split '\s*,\s*' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ }
    
    if ($IDArray.Count -eq 0) {
        return "Error: No valid Event IDs provided"
    }
} catch {
    return "Error: Failed to parse parameters - $($_.Exception.Message)"
}

function Get-UserNameFromSid {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Sid
    )
    process {
        # Handle null/empty SID
        if ([string]::IsNullOrWhiteSpace($Sid)) {
            return [pscustomobject]@{
                SID     = $null
                Account = 'SYSTEM'
                Name    = 'SYSTEM'
                Source  = 'Null SID (System context)'
            }
        }

        # Validate SID format
        try {
            $si = [System.Security.Principal.SecurityIdentifier]$Sid
        } catch {
            return [pscustomobject]@{
                SID     = $Sid
                Account = $null
                Name    = $null
                Source  = 'Invalid SID format'
            }
        }

        # Attempt .NET LSA translation
        try {
            $acct = $si.Translate([System.Security.Principal.NTAccount]).Value
            return [pscustomobject]@{
                SID     = $Sid
                Account = $acct
                Name    = $acct.Split('\')[-1]
                Source  = '.NET Translate'
            }
        } catch {
            # Continue to fallback methods
        }

        # CIM local account lookup
        try {
            $u = Get-CimInstance Win32_UserAccount -Filter "SID='$Sid' AND LocalAccount=TRUE" -ErrorAction Stop
            if ($u) {
                return [pscustomobject]@{
                    SID     = $Sid
                    Account = "$($env:COMPUTERNAME)\$($u.Name)"
                    Name    = $u.Name
                    Source  = 'CIM Win32_UserAccount'
                }
            }
        } catch {
            # Sad panda noises
        }

        # Registry ProfileList
        try {
            $key = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid"
            $path = (Get-ItemProperty -Path $key -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath
            $user = Split-Path $path -Leaf
            return [pscustomobject]@{
                SID     = $Sid
                Account = "$($env:COMPUTERNAME)\$user"
                Name    = $user
                Source  = 'Registry ProfileList'
            }
        } catch {
            # Sadder panda noises
        }

        # SID not resolvable
        [pscustomobject]@{
            SID     = $Sid
            Account = $null
            Name    = $null
            Source  = 'Unresolved'
        }
    }
}

# Build the filter hashtable
$EventViewerFilter = @{
    StartTime    = (Get-Date).AddDays(-$DaysInt)
    LogName      = $LogName
    ProviderName = $ProviderName
    ID           = $IDArray
}

# Query events
try {
    $Events = Get-WinEvent -FilterHashtable $EventViewerFilter -ErrorAction Stop
} catch [System.Exception] {
    if ($_.Exception.Message -match 'No events were found') {
        return 'No matching events detected'
    }
    return "Error: $($_.Exception.Message)"
}

if (-not $Events -or $Events.Count -eq 0) {
    return 'No matching events detected'
}

# Output events in delimited format
foreach ($Event in $Events) {
    # Safely extract UserId
    $userIdValue = if ($Event.UserId) { $Event.UserId.Value } else { $null }
    $sid = Get-UserNameFromSid -Sid $userIdValue
    
    # Sanitize message (remove newlines for single-line output)
    $cleanMessage = ($Event.Message -replace '[\r\n]+', ' ' -replace '\s{2,}', ' ').Trim()
    
    # Truncate message if excessively long (Tanium column limits)
    if ($cleanMessage.Length -gt 500) {
        $cleanMessage = $cleanMessage.Substring(0, 497) + '...'
    }
    
    # Output: TimeCreated~EventID~OpCode~Message~Account~SID
    $accountName = if ($sid.Account) { $sid.Account } else { 'Unknown' }
    $sidValue = if ($sid.SID) { $sid.SID } else { 'N/A' }
    
    "$($Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))~$($Event.Id)~$($Event.OpcodeDisplayName)~$cleanMessage~$accountName~$sidValue"

}
