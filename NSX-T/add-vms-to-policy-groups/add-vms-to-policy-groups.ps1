
param (
    [Parameter (Mandatory = $True, ParameterSetName = "default")]
    [Parameter (Mandatory = $True, ParameterSetName = "removeTempObjects")]
    # NSX Manager IP or FQDN.
    [ValidateNotNullOrEmpty()]
    [string] $NsxManager,
    [Parameter (Mandatory = $True, ParameterSetName = "default")]
    [Parameter (Mandatory = $True, ParameterSetName = "removeTempObjects")]
    # Username used to authenticate to NSX API
    [ValidateNotNullOrEmpty()]
    [string] $Username,
    [Parameter (Mandatory = $True, ParameterSetName = "default")]
    [Parameter (Mandatory = $True, ParameterSetName = "removeTempObjects")]
    # Password used to authenticate to NSX API
    [ValidateNotNullOrEmpty()]
    [string] $Password,
    [Parameter (Mandatory = $True, ParameterSetName = "default")]
    [Parameter (Mandatory = $True, ParameterSetName = "removeTempObjects")]
    # Password used to authenticate to NSX API
    [ValidateScript ( { if ( -not (Test-Path $_) ) { throw "Path containing the JSON files $_ does not exist." } else { $true } })]
    [string] $JsonDirectory,
    [Parameter (Mandatory = $True, ParameterSetName = "default")]
    [Parameter (Mandatory = $True, ParameterSetName = "removeTempObjects")]
    [ValidateNotNullOrEmpty()]
    [string]$groupFileIdentifier,
    [Parameter (Mandatory = $False, ParameterSetName = "default")]
    [Parameter (Mandatory = $False, ParameterSetName = "removeTempObjects")]
    [ValidateSet("Basic", "Remote")]
    [string]$AuthType = "Basic",
    [Parameter (Mandatory = $True, ParameterSetName = "removeTempObjects")]
    [ValidateNotNullOrEmpty()]
    [string]$TempVmPrefix
)

# ------------------------------------------------------------------------------
# No need to modify anything below this line.
# ------------------------------------------------------------------------------
#Requires -Version 5.1
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
            Add-Type $TrustAllCertsPolicy
        }
    
        $script:originalCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy
    }
}

function Invoke-NsxtRestMethod {

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidDefaultValueSwitchParameter", "")]

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
        Write-Debug "Invoke-NsxtRestMethod: Desktop version"
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
        Write-Debug $($irmSplat | ConvertTo-Json -Depth 100)
        Invoke-RestMethod @irmSplat
    }
    else {
        Write-Debug "Invoke-NsxtRestMethod: Core version"
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
        Write-Debug $($irmSplat | ConvertTo-Json -Depth 100)
        Invoke-RestMethod @irmSplat
    }
}

function Start-Log {
    param (
        [string]$file,
        [switch]$overwrite = $False
    )
    # Create the output files if they don't already exist
    if ( -not ( Test-Path $file )) {
        Write-Verbose "$file not found... creating a new one"
        New-Item -Type file $file | Out-Null
        if ( Test-Path $file ) {
            Write-Verbose "file $file created"
        }
    }
    # If the file already exists, then if the OverwriteLogFile is specified, we
    # remove the existing one and create a new log file
    elseif ($overwrite -eq $True) {
        Get-Item $file | Remove-Item
        New-Item -Type file $file | Out-Null
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
    $msgPrefix = "$(Get-Date -f "HH:mm:ss") : $((Get-PSCallStack)[1].Location), $((Get-PSCallStack)[1].Command):"

    switch ($level) {
        "error" {
            Add-Content -Path $Script:logFilename -Value "$msgPrefix ERROR: $msg"
            break
        }
        "debug" {
            Write-Debug "$msgPrefix $msg"
            Add-Content -Path $Script:logFilename -Value "$msgPrefix DEBUG: $msg"
            break
        }
        "warning" {
            Write-Warning "$msgPrefix $msg"
            Add-Content -Path $Script:logFilename -Value "$msgPrefix WARNING: $msg"
            break
        }
        "verbose" {
            Write-Verbose "$msgPrefix $msg"
            Add-Content -Path $Script:logFilename -Value "$msgPrefix VERBOSE: $msg"
            break
        }
        "info" {
            Write-Information "$msgPrefix $msg"
            Add-Content -Path $Script:logFilename -Value "$msgPrefix INFO: $msg"
            break
        }
        "file" {
            Add-Content -Path $Script:logFilename -Value "$msgPrefix FILE: $msg"
            break
        }
        "host" {
            Add-Content -Path $Script:logFilename -Value "$msgPrefix HOST: $msg"
            Write-Host $msg
        }
        default {
            Write-Host "$msg" -ForegroundColor $ForegroundColor
            Add-Content -Path $Script:logFilename -Value "$msgPrefix $msg"
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

function Remove-NsxtPolicyGroup {
    param (
        [Parameter(Mandatory = $False)]
        [String] $DomainId = "default",
        [Parameter(Mandatory = $False)]
        [String] $GroupId,
        [Parameter(Mandatory = $False)]
        [String] $Path
    )

    $uri = New-Object System.UriBuilder("https://$nsxManager")

    if ($PSBoundParameters.ContainsKey('Path')) {
        $uri.path = "/policy/api/v1$Path"
    }
    else {
        $uri.path = "/policy/api/v1/infra/domains/$DomainId/groups"
    }

    if ($PSBoundParameters.ContainsKey('GroupId')) {
        $uri.path = $uri.path + "/$groupId"
    }

    try {
        $response = Invoke-NsxtRestMethod -Method Delete -URI $uri -Headers $script:headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }

}
function Get-VmFromInventory {
    param (
        [string]$DisplayName,
        [string]$ExternalId,
        [object]$Inventory
    )

    if ($PSBoundParameters.ContainsKey('DisplayName')) {
        return ($Inventory | Where-Object { $_.display_name -eq $DisplayName })
    }
    else {
        return $Inventory | Where-Object { $_.external_id -eq $ExternalId }
    }
}

function New-GroupConjunctionExpression {
    param (
        [string]$operator
    )
    $object = [ordered]@{
        "conjunction_operator" = $operator.ToUpper();
        "resource_type"        = "ConjunctionOperator";
        "marked_for_delete"    = $false;
    }

    $object
}

function New-GroupVmExpression {
    param (
        [string[]]$Id
    )
    $object = [ordered]@{
        "member_type"       = "VirtualMachine"
        "resource_type"     = "ExternalIDExpression";
        "marked_for_delete" = $false;
        "external_ids"      = New-Object System.Collections.ArrayList;
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

    Write-Debug $path
    Write-Debug $body
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
Write-Log -Level Info -Msg ('-' * 80)
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
Write-Host -NoNewline "`n  --> Retrieving inventory virtual machines from NSX Manager..."
try {
    $inventoryVms = Get-NsxtPolicyInventoryVm
    Write-Host -ForegroundColor Green "OK"
}
Catch {
    Write-Log -Level Error -Msg "Failed to retrieve inventory virtual machines from NSX Manager."
    Write-Log -Level Error -Msg $_
    Write-Host -ForegroundColor Red "FAILED"
    Write-Host -ForegroundColor Red "  --> Error written to LogFile: $Script:LogFileName`n"
    throw $_
}

# Generate a list of group files based on the file identifier from the directory specified.
$groupJsonFiles = Get-ChildItem -Path $JsonDirectory | Where-Object { $_.name -match $groupFileIdentifier }

$tempGroupsToDelete = New-Object System.Collections.ArrayList

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
#
# If there are any Temporary VM IP Groups created for the migration and added to
# the paths, then when update the group with the external_ids of the visible
# virtual machines, we also remove the corresponding temporary ip vm group. The
# path or the temporary group object will be defined by the tempVmprefix
# parameter and the VM Name.
#
# The script will then also go through and remove all the temporary vm ip groups
# for the virtual machines that are now visible in the inventory. 

foreach ($item in $groupJsonFiles) {
    $missingExternalIds = $False
    Write-Log -Level Info -Msg ('-' * 80)
    Write-Log -Level Verbose -Msg "Loading $groupFileIdentifier file: $($item.name)"

    $json = Get-Content -Path $JsonDirectory$pathSeparator$($item.name) | ConvertFrom-Json
    Write-Host -NoNewline "  --> Processing: $($json.id) ($($json.display_name))..."
    Write-Log -Level Verbose -Msg "$($json.id): Processing group: $($json.display_name)"
    Write-Log -Level Verbose -Msg "$($json.id): Total Expressions found = $(($json.expression).count)"

    foreach ($expression in $json.expression) {
        if ($expression.member_type -eq 'VirtualMachine') {
            $externalIdsToAdd = New-Object System.Collections.ArrayList
            $tempGroupPathsToRemove = New-Object System.Collections.ArrayList
            foreach ($external_id in ($expression.external_ids -split ' ')) {
                Write-Log -Level Verbose -Msg "$($json.id): Processing external_id: $external_id"
                $vm = Get-VmFromInventory -Inventory $inventoryVms -ExternalId $external_id
                if (-not ( $vm) ) {
                    Write-Log -Level ERROR -Msg "$($json.id): External_id not found in NSX-T Inventory: $external_id"
                    $missingExternalIds = $True
                    $completionColor = "Red"
                }
                else {
                    Write-Log -Level Verbose -Msg "$($json.id): Found matching external_id in NSX-T Inventory: $external_id ($($vm.display_name))"
                    $externalIdsToAdd.Add($external_id) | Out-Null
                    if ($TempVmPrefix) {
                        $tempGroupPathsToRemove.Add("/infra/domains/default/groups/$($TempVmPrefix)$($vm.display_name)") | Out-Null
                        $tempGroupsToDelete.Add("/infra/domains/default/groups/$($TempVmPrefix)$($vm.display_name)") | Out-Null
                    }

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
            Write-Host -ForegroundColor Red "FAILED"
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
        $externalIdVmExpression = $group.expression | Where-Object { ($_.resource_type -eq 'ExternalIDExpression') -AND ($_.member_type -eq 'VirtualMachine') }
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

        $pathExpression = $group.expression | Where-Object { $_.resource_type -eq 'PathExpression' }
        if ($pathExpression) {
            # Take a copy of the original paths in the expression. This is
            # because when the array gets converted from JSON, it is a
            # collection of fixed size which means we cannot remove anything
            # from it.
            $expressionPaths = { $pathExpression.paths }.Invoke()

            Write-Log -Level Verbose -Msg "$($json.id): Found existing pathExpression"
            if ($tempGroupPathsToRemove.count -ge 1) {
                Write-Log -Level Verbose -Msg "$($json.id): Found $($tempGroupPathsToRemove.count) path(s) to try and remove from group"
                foreach ($path in $tempGroupPathsToRemove) {
                    if ($expressionPaths -ccontains $path) {
                        Write-Log -Level Verbose -Msg "$($json.id): removing path expression $path"
                        $expressionPaths.Remove($path) | Out-Null
                        $requiresPatch = $True
                    }
                    else {
                        Write-Log -Level Verbose -Msg "$($json.id): Path does not exist in pathExpression: $path"
                    }
                }
    
            }
            $pathExpression.paths = $expressionPaths
        }

        $policyPath = "/infra/domains/default/groups/$($json.id)"

        try {
            if ($requiresPatch -eq $True) {
                Write-Log -Level info -Msg "$($json.id): Patching updated configuration"
                Invoke-PatchPolicyObject -path $policyPath -Body $($group | ConvertTo-Json -Depth 100) | Out-Null
                if ($missingExternalIds -eq $True) {
                    Write-Host -ForegroundColor Green -NoNewline "UPDATED "
                    Write-Host -ForegroundColor Yellow "(Some external_ids missing, check log file)"
                }
                else {
                    Write-Host -ForegroundColor Green "UPDATED"
                }
                Continue

            }
            else {
                Write-Log -Level Verbose -Msg "$($json.id): No updates needing to be patched"
                if ($missingExternalIds -eq $True) {
                    Write-Host -ForegroundColor Green -NoNewline "OK "
                    Write-Host -ForegroundColor Yellow "(Some external_ids missing, check log file)"
                }
                else {
                    Write-Host -ForegroundColor Green "OK"
                }
                Continue
            }
        }
        catch {
            Write-Log -Level Error -Msg "$($json.id): Failed to patch object $policyPath"
            Write-Log -Level Error -Msg "$($json.id): body = $($group | ConvertTo-Json -Depth 100 -Compress)"
            Write-Log -Level Error -Msg $_
            Write-Host -ForegroundColor Red "FAILED: Error patching object $policyPath"
            $completionColor = "Red"
            Continue
        }
    }
    Write-Host -ForegroundColor Cyan "SKIPPED"
}

if ($tempGroupsToDelete.count -ge 1) {
    Write-Log -Level Info -Msg ('-' * 80)
    Write-Log -Level Host -Msg "`n  --> Cleaning up temporary vm ip groups"
    Write-Log -Level verbose -Msg "Identified $($tempGroupsToDelete.count) temporary vm ip group(s) to delete."
    foreach ($groupPath in $tempGroupsToDelete) {
        Write-Log -Level verbose -Msg "Attempting to delete group: $groupPath"
        Remove-NsxtPolicyGroup -Path $groupPath
    }
}

$ElapsedTime = $((Get-Date) - $StartTime)
Write-Log -Level Info -Msg "Script duration = $ElapsedTime"
Write-Host -ForegroundColor Green "`nExecution completed in $($ElapsedTime.Hours):$($ElapsedTime.Minutes):$($ElapsedTime.Seconds)"
Write-Host -ForegroundColor $completionColor "LogFile: $Script:LogFileName`n"