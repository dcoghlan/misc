
param (
    [Parameter (Mandatory = $True, ParameterSetName = "default")]
    # [Parameter (Mandatory = $True, ParameterSetName = "removeTempObjects")]
    # NSX Manager IP or FQDN.
    [ValidateNotNullOrEmpty()]
    [string] $NsxManager,
    [Parameter (Mandatory = $True, ParameterSetName = "default")]
    # [Parameter (Mandatory = $True, ParameterSetName = "removeTempObjects")]
    # Username used to authenticate to NSX API
    [ValidateNotNullOrEmpty()]
    [string] $Username,
    [Parameter (Mandatory = $True, ParameterSetName = "default")]
    # [Parameter (Mandatory = $True, ParameterSetName = "removeTempObjects")]
    # Password used to authenticate to NSX API
    [ValidateNotNullOrEmpty()]
    [string] $Password,
    [Parameter (Mandatory = $False, ParameterSetName = "default")]
    # [Parameter (Mandatory = $False, ParameterSetName = "removeTempObjects")]
    [ValidateSet("Basic", "Remote")]
    [string]$AuthType = "Basic",
    # [Parameter (Mandatory = $True, ParameterSetName = "removeTempObjects")]
    [Parameter (Mandatory = $False, ParameterSetName = "default")]
    [ValidateNotNullOrEmpty()]
    [string]$MigrationTagScope,
    [Parameter (Mandatory = $False, ParameterSetName = "default")]
    [ValidateNotNullOrEmpty()]
    [string]$SegmentPath,
    [Parameter (Mandatory = $False, ParameterSetName = "default")]
    [ValidateNotNullOrEmpty()]
    [string]$Domain = "default"
    
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

function Get-NsxtPolicyPath {
    param (
        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String] $Path
    )

    $uri = New-Object System.UriBuilder("https://$nsxManager/policy/api/v1")

    $uri.path += "$($path)"

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

# ------------------------------------------------------------------------------
# Execution
# ------------------------------------------------------------------------------
$StartTime = Get-Date
$requiresPatch = $False

# Run the init function. This sets up the POSH session to allow connectivity to
# the NSX Manager
_init

$ScriptName = Get-Item ($MyInvocation.MyCommand.Name) | Select-Object -ExpandProperty BaseName
$script:logFileName = "$($ScriptName)_$($StartTime.ToString('yyy-MM-dd-HHmmss')).log"
Start-Log -File $Script:logFileName
Write-Log -Level Info -Msg ('-' * 80)
Write-Log -Level VERBOSE -Msg "Script start time = $StartTime"

# Log some interesting stuff
Write-Log -Level Verbose -Msg "SegmentPath = $segmentPath"
Write-Log -Level Verbose -Msg "MigrationTagScope = $MigrationTagScope"
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

Write-Host -NoNewline "`n  --> Validating segment path exists..."
Write-Log -Level Info -Msg ('-' * 80)

try {
    $segmentDetails = Get-NsxtPolicyPath -Path $SegmentPath
    Write-Host -ForegroundColor Green "OK"
    Write-Log -Level VERBOSE -Msg "segmentDetails received via API.`n$($segmentDetails | ConvertTo-Json -Depth 100)"
}
Catch {
    Write-Log -Level Error -Msg "Failed to validate provided segment path on NSX Manager ($($NsxManager))."
    Write-Log -Level Error -Msg $_
    Write-Host -ForegroundColor Red "FAILED"
    Write-Host -ForegroundColor Red "  --> Error written to LogFile: $Script:LogFileName`n"
    exit
}

Write-Host -NoNewline "  --> Validating segment wrapper group exists..."
try {
    $segmentWrapperGroup = Get-NsxtPolicyPath -Path "/infra/domains/$($Domain)/groups/$($segmentDetails.id)"
    Write-Host -ForegroundColor Green "OK"
    Write-Log -Level VERBOSE -Msg "segmentWrapperGroup received via API.`n$($segmentWrapperGroup | ConvertTo-Json -Depth 100)"
}
Catch {
    Write-Log -Level Error -Msg "Failed to validate segment wrapper group path on NSX Manager ($($NsxManager))."
    Write-Log -Level Error -Msg $_
    Write-Host -ForegroundColor Red "FAILED"
    Write-Host -ForegroundColor Red "  --> Error written to LogFile: $Script:LogFileName`n"
    exit
}

Write-Host -NoNewline "  --> Validating segment wrapper group migration tag exists..."
$segmentMigrationTag = $segmentWrapperGroup.tags | Where-Object { $_.scope -eq $MigrationTagScope }
if (!$segmentMigrationTag) {
    Write-Log -Level Error -Msg "Unable to locate tag pair with with scope '$($MigrationTagScope)'"
    Write-Host -ForegroundColor Cyan "SKIPPING - NO MIGRATION TAGS FOUND"
    Write-Host -ForegroundColor Cyan "  --> Details written to LogFile: $Script:LogFileName`n"
    exit
}
else {
    Write-Host -ForegroundColor Green "OK"
}

# Take a copy of the original expressions. This is because when the array gets
# converted from JSON, it is a collection of fixed size which means we cannot
# remove anything from it.
$segmentWrapperGroup.expression = { $segmentWrapperGroup.expression }.Invoke()

$arrayIndexCounter = 0
Foreach ($expression in $segmentWrapperGroup.expression) {
    foreach ($cidr in $segmentMigrationTag.tag ) {

        if ( ($expression.resource_type -eq "IPAddressExpression") -AND ($expression.ip_addresses -ccontains $cidr ) ) {

            Write-Log -Level VERBOSE -Msg "Found address '$cidr' in IpExpression"

            if ($expression.ip_addresses.count -le 1) {
                Write-Log -Level VERBOSE -Msg "Single IP Address found in expression. Whole expression will be removed."
                if ($segmentWrapperGroup.expression[$arrayIndexCounter + 1].resource_type -eq "ConjunctionOperator") {
                    Write-Log -Level VERBOSE -Msg "Found ConjunctionOperator after IPAddressExpression that will be removed. Removing the Conjunction expression."
                    $segmentWrapperGroup.expression.RemoveAt($arrayIndexCounter + 1)
                }
    
                $segmentWrapperGroup.expression.RemoveAt($arrayIndexCounter)
                if ($segmentWrapperGroup.expression[$arrayIndexCounter - 1].resource_type -eq "ConjunctionOperator") {
                    Write-Host -ForegroundColor Cyan "Also need to delete preceding conjunctor"
                    Write-Log -Level VERBOSE -Msg "Found ConjunctionOperator before IPAddressExpression that will be removed. Removing the Conjunction expression."
                    $segmentWrapperGroup.expression.RemoveAt($arrayIndexCounter - 1)
                }
                $requiresPatch = $True
            }
            else {
                Write-Log -Level VERBOSE -Msg "Found $($expression.ip_addresses.count) address entries. Only going to remove address: '$cidr'"
    
                $expression.ip_addresses = { $expression.ip_addresses }.invoke()
                $expression.ip_addresses.Remove($cidr) | Out-Null
                $requiresPatch = $True
            }
        }
        elseif ($expression.resource_type -eq "IPAddressExpression") {
            Write-Log -Level VERBOSE -Msg "IPAddressExpression does not tag address '$($cidr)'."
        }
        else {
            Write-Log -Level VERBOSE -Msg "Ignoring $($expression.resource_type)"
        }
    }
    $arrayIndexCounter += 1
}

Write-Host -NoNewline "  --> Updating NSX Manager ($($NsxManager))..."
if ($requiresPatch -eq $True) {

    Write-Log -Level VERBOSE -Msg "Group is required to be updated via PATCH"

    # As the IP object has been removed, also remove the migration tag
    $arrayIndexCounter = 0
    $segmentWrapperGroup.tags = { $segmentWrapperGroup.tags }.invoke()
    Foreach ($tagPair in $segmentWrapperGroup.tags) {
        if ($tagPair.scope -eq $MigrationTagScope) {
            Write-Log -Level VERBOSE -Msg "Removing tag pair with scope '$($migrationTagScope)' at index $($arrayIndexCounter)"
            $segmentWrapperGroup.tags.RemoveAt($arrayIndexCounter) | Out-Null
            break
        }
        $arrayIndexCounter += 1
    }

    # Now patch the updated body
    Write-Log -Level VERBOSE -Msg "Patching updated configuration for group: $($segmentWrapperGroup.id)`n$($segmentWrapperGroup | ConvertTo-Json -Depth 100)"
    try {
        Invoke-PatchPolicyObject -path $segmentWrapperGroup.path -Body $($segmentWrapperGroup | ConvertTo-Json -Depth 100) | Out-Null
        Write-Host -ForegroundColor Green "OK"
    }
    catch {
        Write-Log -Level Error -Msg "$($segmentWrapperGroup.id): Failed to patch object $($segmentWrapperGroup.path)"
        Write-Log -Level Error -Msg "$($segmentWrapperGroup.id): body = $($segmentWrapperGroup | ConvertTo-Json -Depth 100 -Compress)"
        Write-Log -Level Error -Msg $_
        Write-Host -ForegroundColor Red "FAILED: Error patching object $($segmentWrapperGroup.path)"
        $completionColor = "Red"
        Continue
    }
}
else {
    Write-Host -ForegroundColor Cyan "SKIPPING - NO UPDATE REQUIRED"
    Write-Log -Level VERBOSE -Msg "No changes required"
}

$ElapsedTime = $((Get-Date) - $StartTime)
Write-Log -Level INFO -Msg "Script duration = $ElapsedTime"
Write-Host -ForegroundColor Green "`nExecution completed in $($ElapsedTime.Hours):$($ElapsedTime.Minutes):$($ElapsedTime.Seconds)"
Write-Host -ForegroundColor $completionColor "LogFile: $Script:LogFileName`n"