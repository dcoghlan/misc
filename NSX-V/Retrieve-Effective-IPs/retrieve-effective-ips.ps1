# Author: Dale Coghlan
# Email: dcoghlan@vmware.com
# Date: February 26th 2021

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
    [string]$Environment,
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string]$InputFile
)

$StartTime = Get-Date
$Prefix = $StartTime.ToString('yyy-MM-dd-HHMMss')

# Add an environment prefix to the file names if provided
if ($PSBoundParameters.ContainsKey('Environment')) {
    $Prefix = "$Environment-$Prefix"
}
$outputFile = "$Prefix-effective-ips.json"
$outputFileLog = "$Prefix-effective-ips.log"

function Write-Log {
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("host", "warning", "verbose", "debug", "error")]
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
    $msgPrefix = "$(Get-Date -f "HH:mm:ss") : $((Get-PSCallStack)[1].Location), $((Get-PSCallStack)[1].Command):"

    switch ($level) {
        "error" {
            Write-Debug "$msgPrefix $msg"
            Add-Content -Path $outputFileLog -Value "$msgPrefix ERROR: $msg"
        }
        "debug" {
            Write-Debug "$msgPrefix $msg"
            Add-Content -Path $outputFileLog -Value "$msgPrefix DEBUG: $msg"
        }
        "warning" {
            Write-Warning "$msgPrefix $msg"
            Add-Content -Path $outputFileLog -Value "$msgPrefix WARNING: $msg"
        }
        "verbose" {
            Write-Verbose "$msgPrefix $msg"
            Add-Content -Path $outputFileLog -Value "$msgPrefix VERBOSE: $msg"
        }
        "file" {
            Add-Content -Path $outputFileLog -Value "$msgPrefix FILE: $msg"
        }
        default {
            Write-Host "[$(Get-Date -f "HH:mm:ss")]: $msg" -ForegroundColor $ForegroundColor
            Add-Content -Path $outputFileLog -Value "$msgPrefix $msg"
        }
    }
}

Write-Log -Level Host -Msg "Logging File: $outputFileLog"
Write-Log -Level Host -Msg "Input File: $InputFile"
Write-Log -Level Host -Msg "Output File: $outputFile"

# Make sure we connect to the NSX Manager provided
if (-not ($global:DefaultNsxConnection)) {
    Write-Log -Level Host -Msg "Establishing a PowerNSX connection to $server"
    Connect-NsxServer -Server $Server -Username $Username -Password $Password -DisableVIAutoConnect -WarningAction SilentlyContinue
}
else {
    Write-Log -Level Host -Msg "Found existing PowerNSX connection: ($($Global:DefaultNSXConnection.Server))"
    Write-Log -Level Host -Msg "Disconnecting from NSX Manager: ($($Global:DefaultNSXConnection.Server))"
    Disconnect-NsxServer
    Write-Log -Level Host -Msg "Establishing new PowerNSX connection to $server"
    Connect-NsxServer -Server $Server -Username $Username -Password $Password -DisableVIAutoConnect -WarningAction SilentlyContinue
}

# Create the output files if they don't already exist
foreach ($file in $outputFileLog) {
    if ( -not ( Test-Path $file )) {
        Write-Verbose "$file not found... creating a new one"
        New-Item -Type file $file | Out-Null
        if ( Test-Path $file ) {
            Write-Verbose "file $outputFile exists"
        }
    }    
}



Write-Log -Level Debug -Msg "PowerNSX Connection Details"
Write-log -Level Debug -Msg ($Global:DefaultNSXConnection | Out-String)

Write-Log -Level Verbose -Msg "Checking file exists: $inputfile"
if (Test-Path -Path $InputFile) {
    $inputData = Get-Content -Path $InputFile | ConvertFrom-Json -AsHashtable
}
else {
    Write-Log -Level Error -Msg "InputFile does not exist: $inputFile"
}

$data = @{}

foreach ($objectId in $inputdata.securitygroup) {
    Write-Log -Level Host -Msg "Retrieving effective ip addresses for object: $objectid"
    try {
        $response = Get-NsxSecurityGroupEffectiveIpAddress -SecurityGroupId $objectId
        if ($response) {
            Write-Log -Level Debug -Msg "$($response | ConvertTo-Json -Depth 100)"
            $data.Add($objectid, $response) | Out-Null
        }
    }
    catch {
        Write-Log -Level Error -Msg $_
    }
}

$data | Export-Clixml -Path $outputFile
Write-Log -Level Host -Msg "Output file saved to: $outputFile"

$ElapsedTime = $((Get-Date) - $StartTime)
Write-Host -ForegroundColor Green "`nExecution completed in $($ElapsedTime.Hours):$($ElapsedTime.Minutes):$($ElapsedTime.Seconds)`n"


