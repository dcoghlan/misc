# Author: Dale Coghlan
# Email: dcoghlan@vmware.com
# Date: April 2nd 2020

param (
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string]$Password,
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string]$Server,
    [parameter(Mandatory = $False)]
    [ValidateNotNullOrEmpty()]
    [string]$Environment
)

$StartTime = Get-Date
$Prefix = $StartTime.ToString('yyy-MM-dd-HHMMss')

# Add an environment prefix to the file names if provided
if ($PSBoundParameters.ContainsKey('Environment')) {
    $Prefix = "$Environment-$Prefix"
}
$outputFile = "$Prefix-details.csv"
$outputFileLog = "$Prefix-log.txt"

Write-Host "`nLogging File: $outputFileLog"
Write-Host "vNic Details: $outputFile`n"

# Initialise some variables
$data = New-Object System.Collections.ArrayList

# Make sure we connect to the NSX Manager provided
if (-not ($global:DefaultNsxConnection)) {
    Write-Host "Establishing a PowerNSX connection to $server"
    Connect-NsxServer -Server $Server -Username $Username -Password $Password -DisableVIAutoConnect -WarningAction SilentlyContinue
}
else {
    Write-host "Found existing PowerNSX connection: ($($Global:DefaultNSXConnection.Server))"
    Write-host "Disconnecting from NSX Manager: ($($Global:DefaultNSXConnection.Server))"
    Disconnect-NsxServer
    Write-Host "Establishing new PowerNSX connection to $server"
    Connect-NsxServer -Server $Server -Username $Username -Password $Password -DisableVIAutoConnect -WarningAction SilentlyContinue
}

# Create the output files if they don't already exist
foreach ($file in $outputFile,$outputFileLog) {
    if ( -not ( test-path $file )) {
        write-verbose "$file not found... creating a new one"
        New-Item -Type file $file | out-null
        if ( test-path $file ) {
            write-verbose "file $outputFile exists"
        }
    }    
}

function Write-Log {
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("host", "warning", "verbose", "debug")]
        [string]$level = "host",
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("white", "yellow", "red", "magenta", "cyan", "green")]
        [string]$ForegroundColor = "white",
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$msg
    )

    $ForegroundColor = "white"
    $msgPrefix = "$(get-date -f "HH:mm:ss") : $((get-pscallstack)[1].Location), $((get-pscallstack)[1].Command):"

    switch ($level) {
        "debug" {
            write-debug "$msgPrefix $msg"
            Add-content -path $outputFileLog -value "$msgPrefix DEBUG: $msg"
        }
        "warning" {
            write-warning "$msgPrefix $msg"
            Add-content -path $outputFileLog -value "$msgPrefix WARNING: $msg"
        }
        "verbose" {
            write-verbose "$msgPrefix $msg"
            Add-content -path $outputFileLog -value "$msgPrefix VERBOSE: $msg"
        }
        "file" {
            Add-content -path $outputFileLog -value "$msgPrefix FILE: $msg"
        }
        default {
            write-host "$msgPrefix $msg" -ForegroundColor $ForegroundColor
            Add-content -path $outputFileLog -value "$msgPrefix $msg"
        }
    }
}

Write-Log -Level Debug -Msg "PowerNSX Connection Details"
Write-log -Level Debug -Msg ($Global:DefaultNSXConnection | Out-String)

# Use Central CLI via API to find all the DFW prepped clusters
Write-host " --> Retrieving DFW Clusters... " -NoNewline
try {
    $queryAllClusters = "show dfw cluster all"
    Write-Log -Level Debug -Msg "Executing: $queryAllClusters"
    $dfwClusters = Invoke-NsxCli -Query $queryAllClusters -WarningAction SilentlyContinue
    Write-Log -Level Debug -Msg ("Response: $($dfwClusters | Format-Table | Out-String)")
    Write-host -ForegroundColor Green "OK"
}
catch {
    Write-Log -Level Debug -Msg ("Error: $_")
    Write-host -ForegroundColor Red "Failed"
}

# Go through each DFW prepped cluster and find all the hosts, then execute the
# summarize-dvfilter command and figure out how many filters are on the host

foreach ($cluster in $dfwClusters) {

    Write-host "`n --> Processing DFW Cluster: $($cluster.'Cluster Name')"
    Write-host "   --> Retrieving DFW Hosts..." -NoNewline

    try {
        $queryDfwCluster = "show dfw cluster $($cluster.'Cluster Id')"
        Write-Log -Level Debug -Msg "Executing: $queryDfwCluster"
        $dfwHosts = Invoke-Nsxcli -query $queryDfwCluster -WarningAction SilentlyContinue
        Write-Log -Level Debug -Msg ("Response: $($dfwHosts | Format-Table | Out-String)")
        Write-host -ForegroundColor Green "OK"
    }
    catch {
        Write-Log -Level Debug -Msg ("Error: $_")
        Write-host -ForegroundColor Red "Failed"
        Break
    }

    foreach ($dfwHost in $dfwHosts) {

        $hostData =[ordered]@{}
        Write-host "     --> Retrieving filters: $($dfwHost.'Host Name')... " -NoNewline

        try {
            $queryDfwHost = "show dfw host $($dfwHost.'Host Id') summarize-dvfilter"
            Write-Log -Level Debug -Msg "Executing: $queryDfwHost"
            $summarizeDvfilterOutput = Invoke-Nsxcli -query $queryDfwHost -RawOutput -WarningAction SilentlyContinue    
            Write-Log -Level Debug -Msg ("Response: $($summarizeDvfilterOutput | Out-String)")
            Write-host -ForegroundColor Green "OK"
        }
        catch {
            Write-Log -Level Debug -Msg ("Error: $_")
            Write-host -ForegroundColor Red "Failed"
            Break
        }
        # Add specific details into a temporary hashtable
        $hostData.Add('cluster_id',$($cluster.'Cluster Id'))
        $hostData.Add('cluster_name',$($cluster.'Cluster Name'))
        $hostData.Add('host_id',$($dfwHost.'Host Id'))
        $hostData.Add('host_name',$($dfwHost.'Host Name'))
        $filters = ($summarizeDvfilterOutput -split "`n") -match "sfw\.2"
        $hostData.Add('sfw.2_count',$($filters.Length))
        $hostData.Add('Date', (Get-Date -f yyyy-MM-dd))
        $hostData.Add('Time', (Get-Date -f HH:MM:ss))

        # Add the hashtable into the global data arraylist
        $data.Add($hostData) | Out-Null
    }
}

# Use the hasthable keys to generate CSV column headers
Add-Content -path $outputFile -value ($data[0].keys -join ', ')

# Add the data from the hashtable into the CSV file
foreach ($object in $data) {
    Add-Content -path $outputFile -value ($object.Values -join ', ')
}

$ElapsedTime = $((get-date) - $StartTime)
write-host -foregroundcolor Green "`nExecution completed in $($ElapsedTime.Hours):$($ElapsedTime.Minutes):$($ElapsedTime.Seconds)`n"


