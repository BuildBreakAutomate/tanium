<#
.SYNOPSIS
	Returns the status of OS bundle files within the Tanium Provision Endpoint cache.
.AUTHOR
    Brent M. Henderson - Build Break Automate LLC
	Copyright (c) 2025 - Build Break Automate LLC. - https://buildbreakautomate.com
	Need help with implementation? Contact me at https://buildbreakautomate.com/index.php/need-help/ for implementation / consulting services.
	Always happy to meet new people; add me on LinkedIn at https://www.linkedin.com/in/brentmhenderson/.
.LICENSE
    MIT License

    Copyright (c) 2025 Build Break Automate LLC

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
param (
    [Parameter(Mandatory = $false)]
    [string]$ProvisionCache = 'C:\Program Files (x86)\Tanium\Tanium Client\Tools\Provision\cache',

    [psobject]$ManifestPath = 'C:\Program Files (x86)\Tanium\Tanium Client\Tools\Provision\cache\manifest.json'
)

if (![System.IO.Directory]::Exists($ProvisionCache)) {
    throw "Cache path '$ProvisionCache' not found"
} 

if (![System.IO.File]::Exists($ManifestPath)) {
    throw "Manifest file '$ManifestPath' not found"
}

$cacheFiles = [System.Collections.Generic.List[psobject]]::new()
$computerName = $env:COMPUTERNAME
$outputObject = [System.Collections.Generic.List[psobject]]::new()

try {
    $manifest = Get-Content -Path $ManifestPath -Raw | ConvertFrom-Json
}
catch {
    throw "Failed to read manifest file: $_"
}

[System.IO.Directory]::EnumerateFiles($ProvisionCache) | ForEach-Object {
    $fi = [System.IO.FileInfo]::new($_)
    
    if ($fi.Name -ne 'manifest.json') {
        $cacheFiles.Add([pscustomobject]@{
                Name = $fi.Name
                Size = $fi.Length
            })
    }
}

foreach ($bundle in $manifest.bundles) {
    $index = 0

    do {
        [PSCustomObject]$file = $bundle.files[$index]

        if ($null -eq $file) {
            break
        }

        # Check if file exists in cache
        $cacheFile = $cacheFiles -match $file.meta.sha256

        # If file is missing from cache, add to output and continue
        if (-not $cacheFile) {
            $outputObject.Add([pscustomobject]@{
                    Bundle       = $bundle.name
                    Name         = $file.Name
                    SHA256       = $file.meta.sha256
                    ExpectedSize = $file.Size
                    CurrentSize  = 0
                    Status       = 'Missing'
                })
            $index++
            continue
        }

        # If file size does not match, mark as downloading
        if ($cacheFile.Size -ne $file.Size) {
            $outputObject.Add([pscustomobject]@{
                    Bundle       = $bundle.name
                    Name         = $file.Name
                    SHA256       = $file.meta.sha256
                    ExpectedSize = $file.Size
                    CurrentSize  = $cacheFile.Size
                    Status       = 'Downloading'
                })
            $index++
            continue
        }

        # If file size matches, mark as cached
        if ($cacheFile.Size -eq $file.Size) {
            $outputObject.Add([pscustomobject]@{
                    Bundle       = $bundle.name
                    Name         = $file.Name
                    SHA256       = $file.meta.sha256
                    ExpectedSize = $file.Size
                    CurrentSize  = $cacheFile.Size
                    Status       = 'Cached'
                })
        }
        $index++
    } until (
        [bool]$(-not $file)
    )
}

foreach ($item in $outputObject) {
    Write-Output "$($computerName)~$($item.Bundle)~$($item.Name)~$($item.SHA256)~$($item.ExpectedSize)~$($item.CurrentSize)~$($item.Status)"
}