
param (
    [parameter(Mandatory = $True)]
    # NSX Manager IP or FQDN.
    [ValidateNotNullOrEmpty()]
    [string] $NsxManager,
    [parameter(Mandatory = $True)]
    # Username used to authenticate to NSX API
    [ValidateNotNullOrEmpty()]
    [string] $Username,
    [parameter(Mandatory = $True)]
    # Password used to authenticate to NSX API
    [ValidateNotNullOrEmpty()]
    [string] $Password,
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $VmExportFile,
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $TagAssignmentByVmFile
)

# ------------------------------------------------------------------------------
# No need to modify anything below this line.
# ------------------------------------------------------------------------------
#Requires -Version 5.1

# ------------------------------------------------------------------------------
# Functions
# ------------------------------------------------------------------------------

function _init {

    if ( $psversiontable.psedition -eq "Desktop" ) {
        # Add TLS1.2 support
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Ssl3

        ## Define class required for certificate validation override.  Version dependant.
        ## For whatever reason, this does not work when contained within a function?
        $TrustAllCertsPolicy = @"
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
    
        if ( -not ("TrustAllCertsPolicy" -as [type])) {
            add-type $TrustAllCertsPolicy
        }
    
        $script:originalCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy
    }
}

function Invoke-NsxtRestMethod {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidDefaultValueSwitchParameter","")]

    param (
        [parameter(Mandatory = $True)]
        [ValidateSet("get", "put", "post", "delete", "patch")]
        [string]$method,
        [parameter(Mandatory = $True)]
        [string]$uri,
        [parameter(Mandatory = $false)]
        [hashtable]$headers = @{ },
        [parameter(Mandatory = $False)]
        [switch]$SkipCertificateCheck = $True,
        [parameter(Mandatory = $false)]
        [string]$body
    )

    if ($psversiontable.psedition -eq "Desktop") {
        #Use splatting to build up the IWR params
        $irmSplat = @{
            "method"  = $method;
            "headers" = $headers;
            "uri"     = $Uri;
        }

        if ( $PsBoundParameters.ContainsKey('Body')) {
            $irmSplat.Add("body", $body)
        }

        if (( -not $ValidateCertificate) -and ([System.Net.ServicePointManager]::CertificatePolicy.tostring() -ne 'TrustAllCertsPolicy')) {
            #allow untrusted certificate presented by the remote system to be accepted
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        Write-Debug $uri
        invoke-RestMethod @irmSplat
    }
    else {
        #Use splatting to build up the IWR params
        $irmSplat = @{
            "method"  = $method;
            "headers" = $headers;
            "uri"     = $Uri;
        }

        if ( $PsBoundParameters.ContainsKey('Body')) {
            $irmSplat.Add("body", $body)
        }
        
        if ($PSBoundParameters.ContainsKey('SkipCertificateCheck')) {
            $irmSplat.Add("SkipCertificateCheck", $SkipCertificateCheck)
        }
        Write-Debug $uri
        Invoke-RestMethod @irmSplat
    }
}

function Start-Log {
    param (
        [string]$file,
        [switch]$overwrite = $False
    )
    # Create the output files if they don't already exist
    if ( -not ( test-path $file )) {
        write-verbose "$file not found... creating a new one"
        New-Item -Type file $file | out-null
        if ( test-path $file ) {
            write-verbose "file $file created"
        }
    }
    # If the file already exists, then if the OverwriteLogFile is specified, we
    # remove the existing one and create a new log file
    elseif ($overwrite = $True) {
        Get-Item $file | Remove-Item
        New-Item -Type file $file | out-null
        Write-Log -Level Debug -Msg "New Logfile created as OverwriteLogFile was enabled."
    }  
}

function Write-Log {
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("info", "host", "warning", "verbose", "debug", "error")]
        [string]$level = "host",
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("white", "yellow", "red", "magenta", "cyan", "green")]
        [string]$ForegroundColor = "white",
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [object]$msg,
        [Parameter(Mandatory = $False)]
        [ValidateNotNullOrEmpty()]
        [string]$file = $Script:logFilename
    )

    $ForegroundColor = "white"
    $msgPrefix = "$(get-date -f "HH:mm:ss") : $((get-pscallstack)[1].Location), $((get-pscallstack)[1].Command):"

    switch ($level) {
        "error" {
            Add-content -path $Script:logFilename -value "$msgPrefix ERROR: $msg"
        }
        "debug" {
            write-debug "$msgPrefix $msg"
            Add-content -path $Script:logFilename -value "$msgPrefix DEBUG: $msg"
        }
        "warning" {
            write-warning "$msgPrefix $msg"
            Add-content -path $Script:logFilename -value "$msgPrefix WARNING: $msg"
        }
        "verbose" {
            write-verbose "$msgPrefix $msg"
            Add-content -path $Script:logFilename -value "$msgPrefix VERBOSE: $msg"
        }
        "info" {
            Write-Information "$msgPrefix $msg"
            Add-content -path $Script:logFilename -value "$msgPrefix INFO: $msg"
        }
        "file" {
            Add-content -path $Script:logFilename -value "$msgPrefix FILE: $msg"
        }
        default {
            write-host "$msg" -ForegroundColor $ForegroundColor
            Add-content -path $Script:logFilename -value "$msgPrefix $msg"
        }
    }
}

function Invoke-LoadFromCliXml {
    param (
        [hashtable]$cliXml,
        [string]$xmltag
    )

    $objectArray = New-Object System.Collections.ArrayList

    foreach ($key in $cliXml.keys) {
        [xml]$xml = $cliXml.item($key)
        $object = $xml.$($xmltag)
        $objectArray.Add($object)
    }
    $objectArray
}

function Get-VmMoref {
    param (
        [string]$ExternalId,
        [hashtable]$masterVms
    )

    Foreach ($moref in $masterVms.keys) {
        if ( ($masterVms.item($moref).instanceuuid -eq $ExternalId) -OR ($masterVms.item($moref).uuid -eq $ExternalId) ) {
            Return $moref
        }
    }
}

function Get-NsxtPolicyInventoryVm {

    param (
        [Parameter(Mandatory = $False)]
        [String] $EnforcementPointId = "default"
    )

    $uri = New-Object System.UriBuilder("https://$nsxManager")

    $uri.path = "/policy/api/v1/infra/realized-state/enforcement-points/$EnforcementPointId/virtual-machines"

    try {
        $response = Invoke-NsxtRestMethod -Method GET -URI $uri -Headers $script:headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }
    $response.results

}

function Add-NsxtPolicyInventoryVmTags {

    param (
        [Parameter(Mandatory = $False)]
        [String] $EnforcementPointId = "default",
        [Parameter(Mandatory = $True)]
        [String] $Id,
        [Parameter(Mandatory = $True)]
        [object[]] $tags
    )

    $uri = New-Object System.UriBuilder("https://$nsxManager")

    $uri.path = "/policy/api/v1/infra/realized-state/enforcement-points/$EnforcementPointId/virtual-machines"
    $uri.query = "action=update_tags"

    $body = @{
        "virtual_machine_id" = $id;
        "tags" = $tags;
    }
    Write-Debug ($body | ConvertTo-Json -depth 100)

    try {
        $response = Invoke-NsxtRestMethod -Method POST -URI $uri -body ($body | ConvertTo-Json -depth 100) -Headers $script:headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }

    $response.results

}

# ------------------------------------------------------------------------------
# Execution
# ------------------------------------------------------------------------------
$StartTime = Get-Date

# Run the init function. This sets up the POSH session to allow connectivity to
# the NSX Manager
_init

$ScriptName = Get-Item ($MyInvocation.MyCommand.Name) | Select-Object -ExpandProperty BaseName
$script:logFileName = "$($ScriptName)_$($StartTime.ToString('yyy-MM-dd-HHmmss')).log"
Start-Log -File $Script:logFileName

# Log some interesting stuff
Write-Log -Level Verbose -Msg "VmExportFile = $VmExportFile"
Write-Log -Level Verbose -Msg "TagAssignmentByVmFile = $TagAssignmentByVmFile"
Write-Log -Level Verbose -Msg "NSX Manager = $NsxManager"
Write-Log -Level Verbose -Msg "NSX Manager Username = $Username"
Write-Log -Level Verbose -Msg "Powershell Edition: $($psversiontable.PSEdition)"
Write-Log -Level Verbose -Msg "Powershell Version: $(($psversiontable.PSVersion).ToString())"
Write-Log -Level Verbose -Msg "Powershell OS: $($psversiontable.OS)"
Write-Log -Level Verbose -Msg "Powershell Platform: $($psversiontable.Platform)"

# This is the color of the log file output at the completion of the script.
# We change this to Red if there are any issue encountered during the sctipt
$completionColor = "Green"


# Create the custom header for authentication
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $Username, $Password)))
$script:headers = @{
    "Authorization" = ("Basic {0}" -f $base64AuthInfo);
    "Content-Type"  = "application/json"
}

# Load the CliXml files
$masterVMs = Import-Clixml -path $VmExportFile
$masterTagAssignmentsByVm = Import-CliXml -Path $TagAssignmentByVmFile

# Retrieve the list of VMs in the inventory
Write-Host "`n  --> Retrieving inventory virtual machines from NSX Manager"
try {
    $inventoryVms = Get-NsxtPolicyInventoryVm -Verbose 4>test.txt
}
Catch {
    Write-Log -Level Error -Msg "Failed to retrieve inventory virtual machines from NSX Manager."
    Write-Log -Level Error -Msg $_
    Write-Host -foregroundcolor Red "  --> Error written to LogFile: $Script:LogFileName`n"
    throw $_
}

foreach ($inventoryVm in $inventoryVms ) {
    Write-Log -Level Info -Msg ("-" * 80)
    Write-host -nonewline "  --> Processing: $($inventoryVm.external_id)..."
    Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Processing VM: $($inventoryVm.display_name)"
    Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Existing Tag count: $(($inventoryVm.tags).count)"

    # Using the external id from NSX-T, lookup the moref from the VmExport.xml file from a NSX-v Object Capture
    $vmMoref = Get-VmMoref -masterVms $masterVms -ExternalId $inventoryVm.'external_id'
    if (-not $vmMoref) {
        Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Skipping VM. No matching VM MoRef found."
        Write-Host -Foregroundcolor Cyan "SKIPPED"
    } else {
        Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Moref = $vmMoref"

        # Using the discovered MoRef, lookup all the NSX-v SecurityTags that were applied to the VM
        $assignedNsxvTags = $masterTagAssignmentsByVm.item($vmMoref)

        if ( -not $assignedNsxvTags) {
            Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): No NSX-v Security Tags assigned"
            Write-Host -Foregroundcolor Cyan "SKIPPED"
            Continue
        }

        # Create a new array so we can keep track of which tags are missing from the
        # inventoryVm so we can add them later
        $tagsToAddArray = New-Object System.Collections.ArrayList

        # Loop through all the tags assigned in NSX-v, and check them against the tags currently assigned in NSX-T.
        foreach ($assignedNsxvTagName in $assignedNsxvTags.name) {
            Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Processing NSX-v tag ($assignedNsxvTagName)"
            if ($InventoryVm.tags.tag -notcontains $assignedNsxvTagName) {
                Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): NSX-v tag ($assignedNsxvTagName) not configured"
                $tagSet = @{
                    "tag" = $assignedNsxvTagName;
                    "scope" = "";
                }
                Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Adding tag ($assignedNsxvTagName) to list of tags to add to vm"
                $tagsToAddArray.Add($tagSet) | Out-Null
            }
            else {
                Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Tag ($assignedNsxvTagName) already exists"
            }
        }

        if ( $tagsToAddArray.count -gt 0 ) {
            Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Found $($tagsToAddArray.count) tags to add"
            # Check to see if the inventoryVM already has the tags property or not
            if (-not ($inventoryVm | Get-Member -MemberType Properties -Name tags)) {
                Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Adding note property"
                $inventoryVm | Add-Member -MemberType NoteProperty -Name 'tags' -Value $tagsToAddArray | Out-Null
            }
            else {
                foreach ($tagToAdd in $tagsToAddArray) {
                    $inventoryVm.tags += $tagToAdd
                }
            }
            Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Updated tag count = $(($inventoryVm.tags).count)"
            try {
                Write-Log -Level Verbose -Msg "$($inventoryVm.external_id): Applying updated tags to inventory virtual machine"
                Add-NsxtPolicyInventoryVmTags -id $inventoryVm.external_id -tags $inventoryVm.tags
                Write-Host -Foregroundcolor Green "UPDATED"
                Continue
            }
            catch {
                Write-Log -Level Error -Msg "$($inventoryVm.external_id): Failed to update tags on inventory virtual machine."
                Write-Log -Level Error -Msg "$($inventoryVm.external_id): Tags to apply = $($inventoryVm.tags | ConvertTo-Json -depth 100 -Compress)"
                Write-Log -Level Error -Msg $_
                Write-Host -Foregroundcolor Red "FAILED"
                $completionColor = "Red"
                Continue
                
            }

        }
        Write-Host -Foregroundcolor Green "OK"
    }
}
$ElapsedTime = $((get-date) - $StartTime)
write-host -foregroundcolor Green "`nExecution completed in $($ElapsedTime.Hours):$($ElapsedTime.Minutes):$($ElapsedTime.Seconds)"
Write-Host -foregroundcolor $completionColor "LogFile: $Script:LogFileName`n"
