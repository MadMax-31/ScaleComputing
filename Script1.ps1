<#
.SYNOPSIS
Script to select certain data from the Scale Cluster

.PARAMETER Server
Cluster/System to test the API against

.PARAMETER Credential
User credentials used to authenticate with the server

.PARAMETER SkipCertificateCheck
Ignore Invalid/self-signed certificate errors

.EXAMPLE
./Script1.ps1 -Server server-name -Credential (Get-Credential)
#>

[CmdletBinding()]

Param(
    [Parameter(Mandatory = $true,Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string] $Server,
    [PSCredential] $Credential = (Get-Credential -Message "Enter Scale HC3 Credentials"),
    [switch] $SkipCertificateCheck
)

$ErrorActionPreference = 'Stop';

$url = "https://$Server/rest/v1"


$restOpts = @{
    Credential = $Credential
    ContentType = 'application/json'
}

if ($PSVersionTable.PSEdition -eq 'Core') {
    $restOpts.SkipCertificateCheck = $SkipCertificateCheck
}
elseif ($SkipCertificateCheck) {
    try
    {
        add-type -ErrorAction stop @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                    ServicePoint srvPoint, X509Certificate certificate,
                    WebRequest request, int certificateProblem) {
                    return true;
                }
            }
"@
    } catch { write-error "Failed to create TrustAllCertsPolicy: $_" }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}


# Many actions are asynchronous, often we need a way to wait for a returned taskTag to complete before taking further action
function Wait-ScaleTask {
    Param(
        [Parameter(Mandatory = $true,Position  = 1, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string] $TaskTag
    )

    $retryDelay = [TimeSpan]::FromSeconds(1)
    $timeout = [TimeSpan]::FromSeconds(300)

    $timer = [Diagnostics.Stopwatch]::new()
    $timer.Start()

    while ($timer.Elapsed -lt $timeout)
    {
        Start-Sleep -Seconds $retryDelay.TotalSeconds
        $taskStatus = Invoke-RestMethod @restOpts "$url/TaskTag/$TaskTag" -Method GET

        if ($taskStatus.state -eq 'ERROR') {
            throw "Task '$TaskTag' failed!"
        }
        elseif ($taskStatus.state -eq 'COMPLETE') {
            Write-Verbose "Task '$TaskTag' completed!"
            return
        }
    }
    throw [TimeoutException] "Task '$TaskTag' failed to complete in $($timeout.Seconds) seconds"
}

# Find all nodes on the cluster
$nodes = Invoke-RestMethod -Method Get -Uri "$url/Node" @restOpts
# Find all drives on the cluster
$drives = Invoke-RestMethod -Method Get -Uri "$url/Drive" @restOpts

# Find all VM's on the cluster
$vms = @()
$vms = Invoke-RestMethod -Method Get -Uri "$url/VirDomain" @restOpts


$nodes | Select-Object uuid,lanIP,memSize,@{Name="SystemMemory";Expression={$_.memSize /1GB}},systemMemUsageBytes,@{Name="systemMemUsageGigaBytes";Expression={$_.systemMemUsageBytes /1GB}},@{Name="FreeSystemMemory";Expression={($_.memSize - $_.systemMemUsageBytes) /1GB}},@{Name="GBInUse";Expression={$_.totalMemUsageBytes /1GB}} | export-csv -Path c:\temp\ScaleNodes.csv -Delimiter ";" -NoTypeInformation
$drives | Select-Object uuid,slot,serialNumber,type,nodeUUID,@{Name="CapacityGB";Expression={[math]::Round($_.capacityBytes /1GB,1)}},@{Name="DiskUsage_GB";Expression={[math]::Round($_.usedBytes /1GB,1)}},@{Name="FreeDisk_GB";Expression={[math]::Round(($_.capacityBytes - $_.usedBytes) /1GB,1)}},isHealthy,reallocatedSectors,errorCount | export-csv -Path c:\temp\ScaleDrives.csv -Delimiter ";" -NoTypeInformation
