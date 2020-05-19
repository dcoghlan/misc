
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
    # Password used to authenticate to NSX API
    [ValidateScript ( { if ( -not (test-path $_) ) { throw "Path containing the JSON files $_ does not exist." } else { $true } })]
    [string] $JsonDirectory,
    [parameter(Mandatory = $False)]
    [ValidateSet("Basic", "Remote")]
    [string]$AuthType = "Basic"
)

# ------------------------------------------------------------------------------
# No need to modify anything below this line.
# ------------------------------------------------------------------------------
#Requires -Version 5.1
$groupFileIdentifier = "_group_"
$pathSeparator = [IO.Path]::DirectorySeparatorChar # This is to determine dynamic path separators
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
    elseif ($overwrite -eq $True) {
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

function Get-NsxtPolicyGroup {
    param (
        [Parameter(Mandatory = $False)]
        [String] $DomainId = "default",
        [Parameter(Mandatory = $False)]
        [String] $GroupId
    )

    $uri = New-Object System.UriBuilder("https://$nsxManager")

    $uri.path = "/policy/api/v1/infra/domains/$DomainId/groups"

    if ($PSBoundParameters.ContainsKey('GroupId')) {
        $uri.path = $uri.path + "/$groupId"
    }

    try {
        $response = Invoke-NsxtRestMethod -Method GET -URI $uri -Headers $script:headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }

    if ($response.results) {
        $response.results
    }
    else {
        $response
    }
}

function Get-VmFromInventory {
    param (
        [string]$DisplayName,
        [string]$ExternalId,
        [object]$Inventory
    )

    if ($PSBoundParameters.ContainsKey('DisplayName')) {
        return ($Inventory | Where-Object {$_.display_name -eq $DisplayName})
    }
    else {
        return $Inventory | Where-Object {$_.external_id -eq $ExternalId}
    }
}

function New-GroupConjunctionExpression {
    param (
        [string]$operator
    )
    $object = [ordered]@{
        "conjunction_operator" = $operator.ToUpper();
        "resource_type"     = "ConjunctionOperator";
        "marked_for_delete" = $false;
    }

    $object
}

function New-GroupVmExpression {
    param (
        [string[]]$Id
    )
    $object = [ordered]@{
        "member_type" = "VirtualMachine"
        "resource_type"     = "ExternalIDExpression";
        "marked_for_delete" = $false;
        "external_ids" = New-Object System.Collections.ArrayList;
    }

    foreach ($item in $Id) {
        $object.external_ids.Add($item) | Out-Null
    }

    $object
}

function Invoke-PatchPolicyObject {
    param (
        [parameter(Mandatory = $True)]
        [object] $path,
        [parameter(Mandatory = $True)]
        [string] $body
    )

    $uri = New-Object System.UriBuilder("https://$nsxManager/policy/api/v1")
    $uri.path += $path

    write-debug $path
    write-debug $body
    Invoke-NsxtRestMethod -method PATCH -body $body -uri $uri -SkipCertificateCheck -Headers $headers

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
Write-Log -Level Info -Msg ('-'*80)
Write-Log -Level Info -Msg "Script start time = $StartTime"

# Log some interesting stuff
Write-Log -Level Verbose -Msg "JsonDirectory = $JsonDirectory"
Write-Log -Level Verbose -Msg "groupFileIdentifier = $groupFileIdentifier"
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
$script:AuthorizationType = (Get-Culture).TextInfo.ToTitleCase($AuthType.ToLower())
$script:headers = @{
    "Authorization" = ("{0} {1}" -f $script:AuthorizationType, $base64AuthInfo);
    "Content-Type"  = "application/json"
}

# Retrieve the list of VMs in the inventory. We use this to see if the 
# VM/external_id is visible to NSX Manager so the external_id can be added to 
# the policy group.
Write-Host "`n  --> Retrieving inventory virtual machines from NSX Manager"
try {
    $inventoryVms = Get-NsxtPolicyInventoryVm
}
Catch {
    Write-Log -Level Error -Msg "Failed to retrieve inventory virtual machines from NSX Manager."
    Write-Log -Level Error -Msg $_
    Write-Host -foregroundcolor Red "  --> Error written to LogFile: $Script:LogFileName`n"
    throw $_
}

# Generate a list of group files based on the file identifier from the directory specified.
$groupJsonFiles = Get-ChildItem -Path $JsonDirectory | Where-Object {$_.name -match $groupFileIdentifier}

# Process each NSX-T Policy Group json file. The configuration in the file is 
# the desired state of the group, however as the VMs didn't exist in the NSX-T
# inventory when the group was created, if we added them via the API (which 
# suprisingly allows you do add an external_id that doesn't exist), it results
# in the group having realization errors, along with every parent/nested group 
# and any firewall rules which use the group.
#
# So we go through and pull out all the virtual_machine external_ids, and then
# check the list of inventory vms from NSX Manager, and only if the external_id
# is seen in NSX Manager do we then add the external_id to the policy group. 
# This allows for a slow/staged migration.

foreach ($item in $groupJsonFiles) {
    $missingExternalIds = $False
    Write-Log -Level Info -Msg ('-'*80)
    Write-Log -Level Verbose -Msg "Loading $groupFileIdentifier file: $($item.name)"

    $json = Get-Content -path $JsonDirectory$pathSeparator$($item.name) | ConvertFrom-Json
    Write-host -nonewline "  --> Processing: $($json.id) ($($json.display_name))..."
    Write-Log -Level Verbose -Msg "$($json.id): Processing group: $($json.display_name)"
    Write-Log -Level Verbose -Msg "$($json.id): Total Expressions found = $(($json.expression).count)"

    foreach ($expression in $json.expression) {
        if ($expression.member_type -eq 'VirtualMachine') {
            $externalIdsToAdd = New-Object System.Collections.ArrayList
            foreach ($external_id in ($expression.external_ids -split ' ')) {
                Write-Log -Level Verbose -Msg "$($json.id): Processing external_id found in $groupFileIdentifier file: $external_id"
                $vm = Get-VmFromInventory -Inventory $inventoryVms -ExternalId $external_id
                if (-not ( $vm) ) {
                    Write-Log -Level ERROR -Msg "$($json.id): External_id not found in NSX-T Inventory: $external_id"
                    $missingExternalIds = $True
                    $completionColor = "Red"
                }
                else {
                    Write-Log -Level Verbose -Msg "$($json.id): Found matching external_id in NSX-T Inventory: $external_id ($($vm.display_name))"
                    $externalIdsToAdd.Add($external_id) | Out-Null
                }
            }        
        }
    }

    # If there are external_ids which have been found in NSX Manager, now we 
    # patch the policy group with the updated list of external_ids.
    if ($externalIdsToAdd.count -gt 0) {
        $requiresPatch = $False
        Write-Log -Level Verbose -Msg "$($json.id): Additional external_ids to add = $($externalIdsToAdd.count)"
        try {
            Write-Log -Level Verbose -Msg "$($json.id): Retrieving group configuration"
            $group = Get-NsxtPolicyGroup -GroupId $json.id
        }
        catch {
            Write-Host -Foregroundcolor Red "FAILED"
            Write-Log -Level Error -Msg "$($json.id): Failed to retrieve group from NSX Manager $policyPath"
            Write-Log -Level Error -Msg $_
            $completionColor = "Red"
            Continue
        }
        # Check to see if the inventoryVM already has the expression property or not
        if (-not ($group | Get-Member -MemberType Properties -Name expression)) {
            Write-Log -Level Verbose -Msg "$($json.id): Adding expression property"
            $expressionProperty = New-Object System.Collections.ArrayList
            $group | Add-Member -MemberType NoteProperty -Name 'expression' -Value $expressionProperty | Out-Null
        }
        $externalIdVmExpression = $group.expression | Where-Object {($_.resource_type -eq 'ExternalIDExpression') -AND ($_.member_type -eq 'VirtualMachine')}
        if ($externalIdVmExpression) {
            Write-Log -Level Verbose -Msg "$($json.id): Found existing VirtualMachine/ExternalIDExpression"
            # Existing expression so we just append to the list
            foreach ($externalIdToAdd in $externalIdsToAdd) {
                if ($externalIdVmExpression.external_ids -notContains $externalIdToAdd) {
                    Write-Log -Level Verbose -Msg "$($json.id): Adding external_id $externalIdToAdd"
                    $externalIdVmExpression.external_ids += $externalIdToAdd
                    $requiresPatch = $True
                }
                else {
                    Write-Log -Level Verbose -Msg "$($json.id): External ID already exists in expression: $externalIdToAdd"
                }
            }
        }
        else {
            Write-Log -Level Verbose -Msg "$($json.id): No existing VirtualMachine/ExternalIDExpression found"
            # no existing expression so we need to add one.

            # however need to figure out if we need to add a conjunctor or not first
            if ($group.expression.count -gt 0) {
                Write-Log -Level Verbose -Msg "$($json.id): Adding Conjunction with OR operator"
                $group.expression += $(New-GroupConjunctionExpression -operator OR)
            }

            # Now lets add the create the externalId expression
            Write-Log -Level Verbose -Msg "$($json.id): Adding new VirtualMachine/ExternalIDExpression"
            $newExpression = New-GroupVmExpression -Id $externalIdsToAdd
            $group.expression += $newExpression
            $requiresPatch = $True
        }

        $policyPath = "/infra/domains/default/groups/$($json.id)"

        try {
            if ($requiresPatch -eq $True) {
                Write-Log -Level info -Msg "$($json.id): Patching updated configuration"
                Invoke-PatchPolicyObject -path $policyPath -Body $($group | ConvertTo-Json -depth 100) | Out-Null
                if ($missingExternalIds -eq $True) {
                    Write-Host -Foregroundcolor Green -NoNewLine "UPDATED "
                    Write-Host -Foregroundcolor Yellow "(Some external_ids missing, check log file)"
                }
                else {
                    Write-Host -Foregroundcolor Green "UPDATED"
                }
                Continue

            }
            else {
                Write-Log -Level Verbose -Msg "$($json.id): No updates needing to be patched"
                if ($missingExternalIds -eq $True) {
                    Write-Host -Foregroundcolor Green -NoNewLine "OK "
                    Write-Host -Foregroundcolor Yellow "(Some external_ids missing, check log file)"
                }
                else {
                    Write-Host -Foregroundcolor Green "OK"
                }
                Continue
            }
        }
        catch {
            Write-Log -Level Error -Msg "$($json.id): Failed to patch object $policyPath"
            Write-Log -Level Error -Msg "$($json.id): body = $($group | ConvertTo-Json -depth 100 -Compress)"
            Write-Log -Level Error -Msg $_
            Write-Host -Foregroundcolor Red "FAILED: Error patching object $policyPath"
            $completionColor = "Red"
            Continue
        }
    }
    Write-Host -Foregroundcolor Cyan "SKIPPED"
}
$ElapsedTime = $((get-date) - $StartTime)
Write-Log -Level Info -Msg "Script duration = $ElapsedTime"
write-host -foregroundcolor Green "`nExecution completed in $($ElapsedTime.Hours):$($ElapsedTime.Minutes):$($ElapsedTime.Seconds)"
Write-Host -foregroundcolor $completionColor "LogFile: $Script:LogFileName`n"