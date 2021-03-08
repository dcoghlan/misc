# Author: Dale Coghlan
# Email: dcoghlan@vmware.com
# Date: March 5th 2021

[CmdletBinding(DefaultParameterSetName = "Default")]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidDefaultValueSwitchParameter", "")]

param (
    [parameter ( Mandatory = $true)]
    [ValidateSet("prepare", "replace", "all")]
    [string]$Mode = "prepare",
    [parameter ( Mandatory = $true, ParameterSetName = "modePrepareVmId")]
    [string[]]$Id,
    [parameter ( Mandatory = $true, ParameterSetName = "modePrepareVmName")]
    [object[]]$VirtualMachine,
    [parameter ( Mandatory = $false, ParameterSetName = "modeReplace")]
    [string]$IpSetPrefix = "MigratedVM",
    [parameter ( Mandatory = $false, ParameterSetName = "modePrepareVmName")]
    [parameter ( Mandatory = $false, ParameterSetName = "modePrepareVmId")]
    [switch]$MultiNicVM = $false,
    [parameter ( Mandatory = $false, ParameterSetName = "modePrepareVmName")]
    [parameter ( Mandatory = $false, ParameterSetName = "modePrepareVmId")]
    [switch]$VmDuplicateName = $false,
    [parameter ( Mandatory = $true, ParameterSetName = "modeReplace")]
    [string[]]$file,
    [parameter ( Mandatory = $false, ParameterSetName = "modeReplace")]
    [ValidateSet("v4", "v6", "both")]
    [string]$IpAddressFamily = "both",
    [parameter ( Mandatory = $false, ParameterSetName = "modeReplace")]
    [parameter ( Mandatory = $false, ParameterSetName = "modePrepareVmName")]
    [parameter ( Mandatory = $false, ParameterSetName = "modePrepareVmId")]
    [switch]$Confirm = $true
)

$script:version = "1.0.0"
$script:StartTime = Get-Date
$Prefix = $script:StartTime.ToString('yyy-MM-dd-HHmmss')
$script:scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name) 
$script:outputLogFile = "$script:scriptName-$Prefix.log"
$script:errorsFound = $false
$script:addressFamilies = New-Object System.Collections.ArrayList

switch ($IpAddressFamily) {
    { ($_ -eq "v4") -or ($_ -eq "both") } {
        $script:addressFamilies.Add("v4") | Out-Null
    }
    { ($_ -eq "v6") -or ($_ -eq "both") } {
        $script:addressFamilies.Add("v6") | Out-Null
    }
}


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

    $msgPrefix = "$(Get-Date -f "HH:mm:ss") : $((Get-PSCallStack)[1].Location), $((Get-PSCallStack)[1].Command):"

    switch ($level) {
        "error" {
            Write-Debug "$msgPrefix $msg"
            Add-Content -Path $script:outputLogFile -Value "$msgPrefix ERROR: $msg"
        }
        "debug" {
            Write-Debug "$msgPrefix $msg"
            Add-Content -Path $script:outputLogFile -Value "$msgPrefix DEBUG: $msg"
        }
        "warning" {
            Write-Warning "$msgPrefix $msg"
            Add-Content -Path $script:outputLogFile -Value "$msgPrefix WARNING: $msg"
        }
        "verbose" {
            Write-Verbose "$msgPrefix $msg"
            Add-Content -Path $script:outputLogFile -Value "$msgPrefix VERBOSE: $msg"
        }
        "file" {
            Add-Content -Path $script:outputLogFile -Value "$msgPrefix FILE: $msg"
        }
        default {
            Write-Host "[$(Get-Date -f "HH:mm:ss")]: $msg" -ForegroundColor $ForegroundColor
            Add-Content -Path $script:outputLogFile -Value "$msgPrefix $msg"
        }
    }
}

function Get-LogDate {
    $(Get-Date -f "HH:mm:ss") 
}

function Get-LogHeaderDetails {
    Write-Host
    Write-Log -Level Host -Msg ('=' * 80)
    Write-Log -Level Host -Msg "Script version: $script:version"
    Write-Log -Level Host -Msg "Script start time: $script:StartTime"
    Write-Log -Level Host -Msg "Logging File: $script:outputLogFile"
    Write-Log -Level Host -Msg "Script mode: $mode"
    Write-Log -Level Host -Msg "IpAddressFamily: $IpAddressFamily"
    Write-Log -Level Host -Msg "AddressFamilies: $($script:addressFamilies -join (', '))"
    Write-Log -Level Host -Msg ('=' * 80)
}

function Invoke-ConnectivityCheck {
    <#
    .SYNOPSIS
        Performs a basic check to make sure a connection to a vCenter and NSX
        Manager are available
    .DESCRIPTION
        Performs a basic check to make sure a connection to a vCenter and NSX
        Manager are available. This is just a rudimentary check, to stop a ton
        of errors being displayed is these connections aren't available.
    #>

    param (
        [parameter ( Mandatory = $false)]
        [ValidateSet("vCenter", "NSXManager", "both")]
        [string]$type = "both"
    )

    $continue = $true

    switch ($type) {
        { ($_ -eq "vCenter") -or ($_ -eq "both") } {
            # Make sure a connection to vCenter is available
            if ($global:DefaultVIServer.isConnected -ne $true) {
                Write-Log -Level Host -ForegroundColor Red -Msg "ERROR: No connection to vCenter found. Please connect to vCenter and try again."
                $continue = $false
            }
        }
        { ($_ -eq "NSXManager") -or ($_ -eq "both") } {
            # Make sure a connection to NSX Manager is available
            if (-not ($global:DefaultNsxConnection)) {
                Write-Log -Level Host -ForegroundColor Red -Msg "ERROR: No connection to NSX Manager found. Please connect to NSX Manager and try again."
                $continue = $false
            }
        }
    }

    if ($continue -eq $false) {
        exit
    }
}

function Invoke-MultiVNicWaring {

    if ( ($script:MultiNicVM) -AND ($script:confirm -eq $true) ) {
        Write-Host -ForegroundColor cyan ("*" * 80)
        Write-Host -ForegroundColor cyan '                                WARNING'
        Write-Host -ForegroundColor cyan 'Processing a multi NIC VM with this script places ALL the VMs IP Addresses into'
        Write-Host -ForegroundColor cyan 'ALL the effective securitygroups. If securitygroups use logicalswitches or vNics'
        Write-Host -ForegroundColor cyan 'in the configuration, more IP addresses than required might be added to the'
        Write-Host -ForegroundColor cyan 'effective security groups.'
        Write-Host
        Write-Host -ForegroundColor cyan 'To suppress this message, use -confirm:$false'
        Write-Host -ForegroundColor cyan ("*" * 80)
        Write-Host "Press any key to continue...`n"
        [void]($Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown'))    
    }
}

function Invoke-LookupVMs {
    <#
    .SYNOPSIS
        Return a VM object from vCenter based on name or moref.
    .DESCRIPTION
        Performs a vCenter lookup for VM objects based on either a VM object,
        or moref (vm-xx or virtualmachine-vm-xx). 
        
        Also checks for multiple VM objects being returned due to duplicate 
        names, or if a vm has multiple vNic, and if either of these are true, 
        then a message/error is displayed and the script execution stopped.
    #>
    param (
        [parameter ( Mandatory = $true)]
        [AllowNull()]
        [object[]]$items
    )

    $vmObjects = New-Object System.Collections.ArrayList
    $continue = $true
    if ($null -eq $items) {
        Write-Log -Level Host -ForegroundColor Red -Msg "ERROR: No virtual machines supplied"
        exit
    }

    ForEach ($vmToLookup in $items) {
        $errorMsg = $null
        if ($vmtolookup -is [string]) {
            Write-Log -Level Verbose -Msg "Processing for lookup: $vmtolookup"
            if ($vmToLookup -cmatch "^VirtualMachine-vm-\d+") {
                Write-Log -Level Verbose -Msg "Performing ID lookup: $vmtolookup"
                $vm = Get-VM -Id $vmToLookup -ErrorAction Ignore
            }
            elseif ($vmToLookup -match "^vm-\d+") {
                Write-Log -Level Verbose -Msg "Performing ID lookup and adding prefix: VirtualMachine-$vmtolookup"
                $vm = Get-VM -Id "VirtualMachine-$vmToLookup" -ErrorAction Ignore
            }
            else {
                Write-Log -Level Verbose -Msg "Performing name string lookup: $vmtolookup"
                $vm = Get-VM $vmToLookup -ErrorAction Ignore
            }
        }
        elseif ($vmtolookup -is [VMware.VimAutomation.ViCore.Interop.V1.VIObjectInterop]) {
            Write-Log -Level Verbose -Msg "Performing VM object lookup: $($vmToLookup.name)"
            $vm = Get-VM $vmToLookup
        }
        else {
            Write-Log -Level host -ForegroundColor Red -Msg "ERROR: Unhandled object type ($($vmToLookup.gettype().BaseType.toString())) to lookup in vCenter"
            $continue = $false
        }


        if ($null -eq $vm) {
            $errorMsg = "ERROR: VM ($vmToLookup) was not found in vCenter - $($global:DefaultVIServer.name)"
            Write-Log -Level Host -ForegroundColor Red -Msg $errorMsg
            $continue = $false
        } 
        elseif ( ($vm.count -gt 1) -AND ($script:VmDuplicateName -eq $false) ) {
            Write-Host -ForegroundColor Red "[$(Get-LogDate)] ERROR: Multiple VMs identified by $vmToLookup were found in vCenter - $($global:DefaultVIServer.name). To target a specific VM, please specify the MoRef. To process both VMs with the same name, use the -VmDuplicateName switch"
            $continue = $false
        }
        else {
            foreach ($v in $vm) {
                if ($script:MultiNicVM -eq $false) {
                    $vmNetworkAdapters = $v | Get-NetworkAdapter
                    if ($vmNetworkAdapters.count -gt 1) {
                        Write-Host -ForegroundColor Red "[$(Get-LogDate)] ERROR: VM with multiple network adapters identified by $vmToLookup were found in vCenter - $($global:DefaultVIServer.name). To process VMs with multiple network adapters, use the -MultiNicVM switch."
                        $continue = $false
                    }
                }
                $vmObjects.Add($v) | Out-Null
            }
        }
    }
    if ($continue) {
        $vmObjects
    }
    else {
        exit
    }

}

function Invoke-FileValidation {
    param (
        [string[]]$file
    )
    Write-Log -Level Host -Msg "Checking to see if files exist"
    $continue = $true
    $failedFiles = New-Object System.Collections.ArrayList
    foreach ($f in $file) {
        if (Test-Path -Path $f) {
            Write-Log -Level Verbose -Msg "Validated file exists: $f"
        }
        else {
            $errorMsg = "File does not exist: $f"
            Write-Log -Level Error -Msg $errorMsg
            $continue = $false
            $failedFiles.Add($f) | Out-Null
        }
    }
    if ($continue -eq $false) {
        $failedMsg = "File validation failed for $failedFiles"
        Write-Log -Level Host -Msg "ERROR: $failedMsg" -ForegroundColor Red
        exit
    }
}

function Invoke-CheckJson {
    param (
        [string[]]$file
    )
    $continue = $true

    foreach ($f in $file) {
        Write-Log -Level verbose -Msg "Loading file $f"
        try {
            Write-Log -Level Verbose -Msg "Importing JSON data from $f"
            $null = Get-Content -Path $f | ConvertFrom-Json -AsHashtable            
            Write-Log -Level Verbose -Msg "Successfully imported JSON data from $f"
        }
        catch {
            $errorMsg = "Unable to load json data from file $f. $_"
            Write-Log -Level Host -ForegroundColor Red -Msg "ERROR: $errorMsg"
            $continue = $false          
        }
    }
    if ($continue -eq $false) {
        exit
    }
}

function Invoke-CheckIpSetExists {
    <#
    .SYNOPSIS
        Checks a collection of IPSets to find a name match
    .DESCRIPTION
        Checks a collection of supplied IPSets to find a name match and returns
        the matched object.
    #>

    param (
        [parameter (Mandatory = $true)]
        [AllowNull()]
        [object[]]$ipsets,
        [parameter (Mandatory = $true)]
        [string]$name
    )
    if ($ipsets.name -contains $name) {
        $ipset = $ipsets | Where-Object { $_.name -eq $name }
        Write-Log -Level Verbose -Msg "IpSet exists: $($ipset.name) ($($ipset.objectid))"
        return $ipset
    }
}

function Invoke-VerifyIpSetAddresses {
    <#
    .SYNOPSIS
        Ensure the IPSet provided matches the discovered addresses provided.
    .DESCRIPTION
        Compare existing IP set to discovered IPs from spoofguard information. If
        the existing IPSet is empty, and there are discovered addresses, then add
        these to the IPSets appropriately. If there are already addresses in the
        IPSet, then remove any that aren't in the discovered addresses list, and
        add any that are missing from the IPSet as required.
    #>

    param (
        [parameter (Mandatory = $true)]
        [object]$ipset,
        [parameter (Mandatory = $true)]
        [object[]]$DiscoveredAddresses
    )

    if ($null -eq $ipset.value) {
        Write-Host "[$(Get-LogDate)] Existing IPSet value is blank, updating with values $($DiscoveredAddresses -join ',')"
        $ipset | Add-NsxIpSetMember -IPAddress $DiscoveredAddresses | Out-Null
    }
    else {
        $removeFromIpSet = Compare-Object -ReferenceObject $($ipset.value -split (",")) -DifferenceObject $DiscoveredAddresses | Where-Object { $_.sideIndicator -eq "<=" } | Select-Object -ExpandProperty InputObject
        $AddToIpSet = Compare-Object -ReferenceObject $($ipset.value -split (",")) -DifferenceObject $DiscoveredAddresses | Where-Object { $_.sideIndicator -eq "=>" } | Select-Object -ExpandProperty InputObject

        if ($AddToIpSet) { 
            Write-Log -Level Host -ForegroundColor Green -Msg "Adding missing values ($($AddToIpSet -join ',')) to IPSet $($ipset.name) ($($ipset.objectid))."
            Get-NsxIpSet -objectId $ipset.objectid | Add-NsxIpSetMember -IPAddress $($AddToIpSet -join ",") | Out-Null
        }
        else {
            Write-Log -Level Verbose -Msg "Nothing required to be added to IP Set"
        }

        if ($removeFromIpSet) {
            Write-Log -Level Host -ForegroundColor Magenta -Msg "Removing old values ($($removeFromIpSet -join ',')) from IPSet $($ipset.name) ($($ipset.objectid))."
            Get-NsxIpSet -objectId $ipset.objectid | Remove-NsxIpSetMember -IPAddress $removeFromIpSet | Out-Null
        }
        else {
            Write-Log -Level Verbose -Msg "Nothing required to be removed from IP Set"
        }
    }
}

function Find-ObjectInGroupConfig {
    <#
    .SYNOPSIS
        Searches a security group to find any references to the objectIds supplied.
    .DESCRIPTION
        Given an array of securitygroup objects, and an objectId, will search the 
        securitygroup configurations for any reference of the objectId in either
        the include members, exclude members, or dynamic criteria.
        
        Returns a hash table of the various groups the object is a member of, 
        split into, Include, Exclude and DynamicCriteria
    #>
    param (
        [parameter (Mandatory = $true)]
        [string]$objectId,
        [parameter (Mandatory = $true)]
        [object[]]$SecurityGroup
    )
    $data = @{}
    
    $arrayInclude = New-Object System.Collections.ArrayList
    $arrayExclude = New-Object System.Collections.ArrayList
    $arrayDynamicCriteria = New-Object System.Collections.ArrayList
    
    $includeGroups = $SecurityGroup | Where-Object { $_.member.objectId -eq $objectId }
    ForEach ($includeGroup in $includeGroups) {
        $arrayInclude.Add(@{"name" = $includeGroup.name; "objectId" = $includeGroup.objectId }) | Out-Null
    }

    $excludeGroups = $SecurityGroup | Where-Object { $_.excludeMember.objectId -eq $objectId }
    ForEach ($excludeGroup in $excludeGroups) {
        $arrayExclude.Add(@{"name" = $excludeGroup.name; "objectId" = $excludeGroup.objectId }) | Out-Null
    }

    $dynamicCriteriaGroups = $SecurityGroup | Where-Object { $_.dynamicmemberdefinition.dynamicset.dynamicCriteria.value -eq $objectId }
    ForEach ($dynamicCriteriaGroup in $dynamicCriteriaGroups) {
        $arrayDynamicCriteria.Add(@{"name" = $dynamicCriteriaGroup.name; "objectId" = $dynamicCriteriaGroup.objectId; "dynamicMemberDefinition" = ($dynamicCriteriaGroup.dynamicMemberDefinition.outerxml) }) | Out-Null
    }

    $data.Add("Include", $arrayInclude) | Out-Null
    $data.Add("Exclude", $arrayExclude) | Out-Null
    $data.Add("DynamicCriteria", $arrayDynamicCriteria) | Out-Null
    $data
}

function Get-SpoofguardNicAddress {
    <#
    .SYNOPSIS
        Returns all valid IP Addresses from a vNics spoofguard configuration
    .DESCRIPTION
        Creates a array of spoofguard published and detected IP addresses from
        a supplied vNics spoofguard information 
    #>
    param (
        [parameter (Mandatory = $true)]
        [object]$object
    )

    $data = New-Object System.Collections.ArrayList
    $published = $object.publishedIpAddress.ipAddress
    $detected = $object.detectedIpAddress.ipAddress

    foreach ($detectedIp in $detected) {
        if ($data -notcontains $detectedIp) {
            $data.Add($detectedIp) | Out-Null
        }
    }

    foreach ($publishedIp in $published) {
        if ($data -notcontains $publishedIp) {
            $data.Add($publishedIp) | Out-Null
        }
    }
    $data

}

function Invoke-RetrieveAllObjects {
    <#
    .SYNOPSIS
        Grabs a copy of all required objects to use as an offline cache for
        speedy lookups.
    .DESCRIPTION
        Grabs a copy of all required objects to use as an offline cache for
        speedy lookups.
    #>
    Write-Log -Level Host -Msg ("=" * 80)
    Write-Log -Level Host -Msg "Retrieving NSX-v Security Groups"
    $script:allSecurityGroups = Get-NsxSecurityGroup
    Write-Log -Level Host -Msg "Retrieving NSX-v IPSets"
    $script:existingIpSets = Get-NsxIpSet
    Write-Log -Level Host -Msg "Retrieving NSX-v SpoofguardPolicies"
    $script:allSpoofGuardPolicies = Get-NsxSpoofguardPolicy
    Write-Log -Level Host -Msg "Retrieving NSX-v Spoofguard NIC details"
    $script:allSpoofGuardNics = $script:allSpoofGuardPolicies | Get-NsxSpoofguardNic
}

function Invoke-PrepareInformation {
    <#
    .SYNOPSIS
        Generates a JSON file that contains all relevant information to be used
        to create an IPSet object for the VM which can be added to all the
        effective NSX-V securitygroups.
    .DESCRIPTION
        Given a list of VMs, either by VM object, VM Name or moref, retrieve 
        the following information:
            - vm name
            - vm moref
            - all ip addresses for the entire VM
            - all security tags applied to the virtual machine
            - all 'effective' security groups
            - all security groups where the VM is defined as a include member 
            - all security groups where the VM is defined as a exclude member 
            - all security groups where the VM is defined in a dynamic criteria
            - all vNics
            - all security groups where the vNic is defined as a include member 
            - all security groups where the vNic is defined as a exclude member 
            - all security groups where the vNic is defined in a dynamic criteria
            - all ip addresses for each individual vNic
        The retrieved information is then saved to disk to be used in by the 
        'replace' mode of the script.
    #>
    param (
        [object[]]$vm
    )

    foreach ($vm in $script:vms) {
        $vmLogIdentifier = "$($vm.name) ($($vm.ExtensionData.MoRef.Value))"
    
        Write-Log -Level Host -Msg ("-" * 80)
        Write-Log -Level Host -Msg "Processing VM: $vmLogIdentifier"

        # Find all security tags assigned to the VM
        Write-Log -Level Verbose -Msg "Retrieving security tags assigned to vm $vmLogIdentifier"
        $vmTags = $vm | Get-NsxSecurityTagAssignment
    
        # Find all the effective security groups that the VM is a member of. This could
        # be from either direct membership, dynamic criteria, dynamic membership (via 
        # logical switch, cluster, dc etc) or security group nesting. This list of 
        # security groups will need to be populated with the IPSet representing the VM.
        Write-Log -Level Verbose -Msg "Retrieving effective security groups for vm $vmLogIdentifier"
        $vmEffectiveGroups = $vm | Get-NsxSecurityGroup

        # Grab all the spoofguard details for a VM, as it contains all the IP address
        # information known about a given VM or vNIC
        Write-Log -Level Verbose -Msg "Retrieving all spoofguard nic details for vm $vmLogIdentifier"
        $vmSpoofGuardNics = $script:allSpoofGuardNics | Where-Object { $_.nicName -match $vm.name }    
    
        #-------------------------------------------------------------------------------
        # Save everything relevant
        $vmData = @{};

        $vmData.Add("virtualMachine", $(Find-ObjectInGroupConfig -objectId $vm.ExtensionData.Moref.value -SecurityGroup $script:allSecurityGroups))
    
        $vmData['virtualMachine'].Add("moref", $vm.ExtensionData.Moref.value)
        $vmData['virtualMachine'].Add("name", $vm.name)
        
        $vmData['virtualMachine']['ipAddress'] = @{}
        $vmData['virtualMachine']['ipAddress'].Add('v4', $(New-Object System.Collections.ArrayList))
        $vmData['virtualMachine']['ipAddress'].Add('v6', $(New-Object System.Collections.ArrayList))
    
        # Saving the security tags applied to the VM
        $vmTagData = New-Object System.Collections.ArrayList
        ForEach ($tag in $vmTags.securitytag) {
            $vmTagData.Add(@{"name" = $tag.name; "objectId" = $tag.objectId }) | Out-Null
        }
        $vmData['virtualMachine'].Add('tags', $vmTagData)
    
        # Saving the effective security group membership for the VM
        $vmDataEffectiveGroups = New-Object System.Collections.ArrayList
        ForEach ($effectiveGroup in $vmEffectiveGroups) {
            # Grab the effective vNics related to the effective group, and keep
            # the ones for this VM with the effective group information.
            $vmDataEffectiveVnics = New-Object System.Collections.ArrayList
            $effectiveVnics = $effectiveGroup | Get-NsxSecurityGroupEffectiveVnic
            $effectiveVnics.uuid | Where-Object { $_ -match "^$($vm.PersistentId)" } | ForEach-Object { $vmDataEffectiveVnics.Add($_) | Out-Null }

            $vmDataEffectiveGroups.Add(@{"name" = $effectiveGroup.name; "objectId" = $effectiveGroup.objectId; "virtualNic" = $vmDataEffectiveVnics }) | Out-Null
        }
        $vmData.Add('effectiveGroups', $vmDataEffectiveGroups)
    
        # Saving all the network adapter info
        $vmData['virtualNic'] = @{}
        ForEach ($networkAdapter in $($vm | Get-NetworkAdapter)) {
            # Generate the vNic objectId
            $networkAdapterObjectId = "$($vm.PersistentId).$($networkAdapter.extensiondata.key.tostring().trimstart('4'))"
            
            # Find any configuration references to the vNic
            $vmData['virtualNic'].Add($networkAdapterObjectId, $(Find-ObjectInGroupConfig -objectId $networkAdapterObjectId -SecurityGroup $script:allSecurityGroups))
            
            # Get all the addresses for each network adapter from spoofguard.
            $networkAdapterSpoofGuardDetails = $vmSpoofGuardNics | Where-Object { $_.id -eq $networkAdapterObjectId }
            $allNetworkAdapterAddresses = Get-SpoofguardNicAddress -object $networkAdapterSpoofGuardDetails
            $v4Addresses = $allNetworkAdapterAddresses | Where-Object { ([ipaddress]$_).AddressFamily -eq 'InterNetwork' }
            $v6Addresses = $allNetworkAdapterAddresses | Where-Object { ([ipaddress]$_).AddressFamily -eq 'InterNetworkV6' }
            $vmData['virtualNic'][$networkAdapterObjectId]['ipAddress'] = @{}
            $vmData['virtualNic'][$networkAdapterObjectId]['ipAddress'].Add('v4', $(New-Object System.Collections.ArrayList))
            $vmData['virtualNic'][$networkAdapterObjectId]['ipAddress'].Add('v6', $(New-Object System.Collections.ArrayList))
    
            if ($v4Addresses) {
                Write-Log -Level Verbose -Msg "Adding IPv4 addresses $v4Addresses to $vmLogIdentifier"
                $v4Addresses | ForEach-Object { $vmData['virtualMachine']['ipAddress']['v4'].Add($_) | Out-Null }
                $v4Addresses | ForEach-Object { $vmData['virtualNic'][$networkAdapterObjectId]['ipAddress']['v4'].Add($_) | Out-Null }
            }
            else {
                $errorMsg = "ERROR: No IPv4 Addresses found for $vmLogIdentifier"
                Write-Log -Level host -ForegroundColor Red -Msg $errorMsg
                $script:errorsFound = $true
            }

            if ($v6Addresses) {
                Write-Log -Level Verbose -Msg "Adding IPv6 addresses $v6Addresses to $vmLogIdentifier"
                $v6Addresses | ForEach-Object { $vmData['virtualMachine']['ipAddress']['v6'].Add($_) | Out-Null }
                $v6Addresses | ForEach-Object { $vmData['virtualNic'][$networkAdapterObjectId]['ipAddress']['v6'].Add($_) | Out-Null }
            }
            else {
                $errorMsg = "WARNING: No IPv6 Addresses found for $vmLogIdentifier" 
                Write-Log -Level host -ForegroundColor Yellow -Msg $errorMsg
            }
        }
        
        $vmFileName = "$($script:scriptName)_$($vm.name)_$($vm.ExtensionData.MoRef.Value)_prepare.json"
        Write-Log -Level Host -Msg  "Persisting data to disk for VM $vmLogIdentifier ($vmFileName)"
        $vmdata | ConvertTo-Json -Depth 100 | Out-File "$vmFileName"
    }
}


function Invoke-ReplaceVmWithIpSet {
    <#
    .SYNOPSIS
        Using the JSON file created by the 'prepare' mode, add the IPSet
        representing the VM to all the effective securitygroups. 
    .DESCRIPTION
        Using the JSON file created by the 'prepare' mode as input, create an 
        IPSet (both v4 and v6) containing the addresses for the VM. If a IPSet 
        already exists which matches the name, then make sure it has the correct
        IP Addresses for the VM. The script will add any addresses missing from 
        the IPSet and any extra addresses in the IPSet which aren't in the JSON 
        file, will be removed from the IPSet.
        The IPSet will then be added to all the 'effectiveSecurityGroups' for 
        the VM if it isn't already a included member.
        The created IPSet information is added to the JSON file and saved with 
        '_complete' appended to the name of the file.

    #>
    param (
        [string[]]$file
    )

    Invoke-RetrieveAllObjects

    foreach ($f in $file) {
        Write-Log -Level Host -Msg ("-" * 80)
        Write-Log -Level Verbose -Msg "Reading file: $f"
        $jsonData = Get-Content -Path $f | ConvertFrom-Json -AsHashtable  
        Write-Log -Level Host -Msg "Processing VM: $($jsonData['virtualMachine']['name'])($($jsonData['virtualMachine']['moref']))"

        if ($jsonData) {

            # Check to see if the virtualmachine IPSet key exists, and if not create it.
            if (! ($jsonData['virtualMachine']['ipset'])) {
                $jsonData['virtualMachine']['ipset'] = @{}
            }

            # Check through the effective group information, specifically the 
            # virtualNics, and compare it against the virtualNic information learnt
            # about the VM. If the count of the effective virtualNics in each 
            # effective groups matches the number of virtualNics discovered from
            # the virtual machine, then it is assumed that only "VM Objects" are
            # consumed. If the number differs in 1 or more groups, then a virtualNic
            # is used somewhere, and its required that we create IPSets for all the
            # individual virtualNics so they can be added individually as required
            # to the effective groups.
            $multiVnicIpSetsRequired = $false
            $vmVnicCount = $jsonData['virtualNic'].count
            Write-Log -Level Verbose -Msg "Virtual machine vNic count = $vmVnicCount"
            foreach ($effectiveGroup in $jsonData['effectiveGroups']) {
                if ($effectiveGroup['virtualNic'].count -ne $vmVnicCount) {
                    $multiVnicIpSetsRequired = $true
                    Write-Log -Level Verbose -Msg "Found group $($effectiveGroup.name) ($($effectiveGroup.objectId)) with effective vNic count ($($effectiveGroup['virtualNic'].count)) that differs from virtual machine vnic count ($vmVnicCount)"
                }
            }

            foreach ($addressFamily in $script:addressFamilies) {
                Write-Log -Level Verbose -Msg "Processing $addressfamily address family."

                $jsonData['virtualMachine']['ipset'].Add($addressFamily, @{})
                # Generate the name for the IP Set
                $newIpSetName = "$($ipsetPrefix)_$($addressFamily)_$($jsonData['virtualMachine']['name'])_$($jsonData['virtualMachine']['moref'])"
                # Using the generated name, check to see if it already exists, and if it does, save it as a variable
                Write-Log -Level Verbose -Msg "Checking for existing IPSet with name $newIpSetName"
                $vmIpSet = Invoke-CheckIpSetExists -ipsets $script:existingIpSets -name $newIpSetName

                # Check to see if there are known IP Addresses for the VM
                $knownAddresses = $jsonData['virtualMachine']['ipAddress'][$addressFamily]
                if ($knownAddresses) {
                    # Check if an IPSet already exists for the VM, and if one doesn't then create it.
                    if ($null -eq $vmIpSet) {
                        Write-Log -Level Verbose -Msg "Creating new IPSet $($newIpSetName) ($($knownAddresses -join ","))"
                        # Create the IP set to represent the VM. This will be added to the effective 
                        # security groups that the migrated VM is/was a member of.
                        $vmIpSet = New-NsxIpSet -Name $newIpSetName -IPAddress $knownAddresses -EnableInheritance
                        $jsonData['virtualMachine']['ipset'][$addressFamily].Add("name", $vmIpSet.name)
                        $jsonData['virtualMachine']['ipset'][$addressFamily].Add("objectId", $vmIpSet.objectId)
                        $jsonData['virtualMachine']['ipset'][$addressFamily].Add("value", $($knownAddresses -join ","))
                    }
                    else {
                        Write-Log -Level Verbose -Msg "Existing IPSet exists for the VM. Determining changes required for VM IPSet $($vmIpSet.name) ($($vmIpSet.objectId))"
                        Invoke-VerifyIpSetAddresses -ipset $vmIpSet -DiscoveredAddresses $knownAddresses
                        $jsonData['virtualMachine']['ipset'][$addressFamily].Add("name", $vmIpSet.name)
                        $jsonData['virtualMachine']['ipset'][$addressFamily].Add("objectId", $vmIpSet.objectId)
                        $jsonData['virtualMachine']['ipset'][$addressFamily].Add("value", $($knownAddresses -join ","))
                    }

                    if ($multiVnicIpSetsRequired) {
                        Write-Log -Level Verbose -Msg "Multiple vNIC IPSets are required to be created."

                        foreach ($virtualNic in $jsonData['virtualNic'].keys) {

                            if (! ($jsonData['virtualNic'][$virtualNic]['ipset'])) {
                                $jsonData['virtualNic'][$virtualNic]['ipset'] = @{}
                            }
                            $jsonData['virtualNic'][$virtualNic]['ipset'].Add($addressFamily, @{})

                            $newVnicIpSetName = "$($ipsetPrefix)_$($addressFamily)_$($jsonData['virtualMachine']['name'])_$($jsonData['virtualMachine']['moref'])_$virtualNic"

                            # Using the generated name, check to see if it already exists, and if it does, save it as a variable
                            Write-Log -Level Verbose -Msg "Checking for existing IPSet with name $newVnicIpSetName"
                            $vnicIpSet = Invoke-CheckIpSetExists -ipsets $script:existingIpSets -name $newVnicIpSetName

                            $vnicKnownAddresses = $jsonData['virtualNic'][$virtualNic]['ipAddress'][$addressFamily]
                            if ($vnicKnownAddresses) {
                                if ($null -eq $vnicIpSet) {
                                    Write-Log -Level Verbose -Msg "Creating new vNic IPSet $($newVnicIpSetName) ($($vnicKnownAddresses -join ","))"
                                    # Create the IP set to represent the vnic. This will be added to the effective 
                                    # security groups that the vnic is/was a member of.
                                    $vnicIpSet = New-NsxIpSet -Name $newVnicIpSetName -IPAddress $vnicKnownAddresses -EnableInheritance
                                    $jsonData['virtualNic'][$virtualNic]['ipset'][$addressFamily].Add("name", $vnicIpSet.name)
                                    $jsonData['virtualNic'][$virtualNic]['ipset'][$addressFamily].Add("objectId", $vnicIpSet.objectId)
                                    $jsonData['virtualNic'][$virtualNic]['ipset'][$addressFamily].Add("value", $($vnicKnownAddresses -join ","))
                                }
                                else {
                                    Write-Log -Level Verbose -Msg "Existing vNic IPSet exists. Determining changes required for vNic IPSet $($vnicIpSet.name) ($($vnicIpSet.objectId))"
                                    Invoke-VerifyIpSetAddresses -ipset $vnicIpSet -DiscoveredAddresses $vnicKnownAddresses
                                    $jsonData['virtualNic'][$virtualNic]['ipset'][$addressFamily].Add("name", $vnicIpSet.name)
                                    $jsonData['virtualNic'][$virtualNic]['ipset'][$addressFamily].Add("objectId", $vnicIpSet.objectId)
                                    $jsonData['virtualNic'][$virtualNic]['ipset'][$addressFamily].Add("value", $($vnicKnownAddresses -join ","))
                                }
                            }
                            
                        }
                    }
                    Write-Log -Level Verbose -Msg "Storing IPSet data for VM $($jsonData['virtualMachine']['name']) ($($jsonData['virtualMachine']['moref']))"
                    $completeFileName = "$([System.IO.Path]::GetFileNameWithoutExtension($f).trimEnd('_prepare'))_complete.json"
                    $jsonData | ConvertTo-Json -Depth 100 | Out-File -path $completeFileName
                    
                    # Add the required IPSet/s into the appropriate effective securitygroups
                    ForEach ($effectiveGroup in ($jsonData['effectiveGroups'] | Where-Object { $_.name -notmatch "^internal_security_group_for_" })) {

                        # Check to see if we need to process vNics individually, or we can just use the VM IPSet
                        if ($effectiveGroup['virtualNic'].count -ne $vmVnicCount) {
                            foreach ($effectiveVnicUuid in $effectiveGroup['virtualNic']) {
                                Write-Log -Level Verbose -Msg "Retrieving latest configuration for effective security group $($effectiveGroup.name) ($($effectiveGroup.objectId))"
                                $g = Get-NsxSecurityGroup -objectId $effectiveGroup.objectId
                                $vNicIpset = $jsondata['virtualNic'][$effectiveVnicUuid]['ipset'][$addressFamily]
                                if ($g.member.objectId -notcontains $vNicIpset.objectId) {
                                    Write-Log -Level Host -Msg "Adding vNic IPSet $($vNicIpset['name']) ($($vNicIpset['objectId'])) to effective security group $($g.name) ($($g.objectId))"
                                    $g | Add-NsxSecurityGroupMember -Member $vNicIpset['objectId']
                                }
                                else {
                                    Write-Log -Level Verbose -Msg "Found vNic IPSet $($vNicIpset.name) ($($vNicIpset.objectId)) is already added to the effective security group $($g.name) ($($g.objectId))"
                                }
                            }
                        }
                        else {
                            Write-Log -Level Verbose -Msg "Retrieving latest configuration for effective security group $($effectiveGroup.name) ($($effectiveGroup.objectId))"
                            $g = Get-NsxSecurityGroup -objectId $effectiveGroup.objectId
                            if ($g.member.objectId -notcontains $vmIpSet.objectId) {
                                Write-Log -Level Host -Msg "Adding VM IPSet $($vmIpSet.name) ($($vmIpSet.objectId)) to effective security group $($g.name) ($($g.objectId))"
                                $g | Add-NsxSecurityGroupMember -Member $vmIpSet
                            }
                            else {
                                Write-Log -Level Verbose -Msg "Found VM IPSet $($vmIpSet.name) ($($vmIpSet.objectId)) is already added to the effective security group $($g.name) ($($g.objectId))"
                            }
                        }
                    }
                }
                else {
                    # Since there are no know addresses from the $addressFamily address family.
                    Write-Log -Level Host -ForegroundColor Red -Msg "ERROR: No known IP$addressFamily addresses defined in the JSON file: $f"
                    if ($vmIpSet) {
                        Write-Log -Level ERROR -Msg "Although there are no known IP$addressFamily addresses defined, found existing IPSet $($vmIpSet.name) ($($vmIpSet.objectId)) with values: $($vmIpSet.value -join ', ')."
                    }
                }
                Write-Log -Level Verbose -Msg "Finished processing $addressfamily address family."
            }
        }
    }
}

################################################################################
# Script Execution
################################################################################

switch ($script:mode) {
    "prepare" {
        Get-LogHeaderDetails
        Invoke-ConnectivityCheck -type both
        Invoke-MultiVNicWaring
        Write-Log -Level Host -Msg "Retrieving virtual machines"
        $script:vms = Invoke-LookupVMs -Items $VirtualMachine
        Invoke-RetrieveAllObjects 
        Invoke-PrepareInformation -vm $script:vms
        break
    }
    "replace" {
        Get-LogHeaderDetails
        Invoke-ConnectivityCheck -type NSXManager
        Invoke-MultiVNicWaring
        Invoke-FileValidation -file $file
        Invoke-CheckJson -file $file
        Invoke-ReplaceVmWithIpSet -file $file
        break
    }
}

if ($script:errorsFound) {
    Write-Host
    Write-Log -Level Host -ForegroundColor Red -Msg "$('*' * 80)"
    Write-Log -Level Host -ForegroundColor Red -Msg "Errors found during execution. Please check log file for details."
    Write-Log -Level Host -ForegroundColor Red -Msg "$('*' * 80)`n"
}

$ElapsedTime = $((Get-Date) - $StartTime)
Write-Host
Write-Log -Level Host -ForegroundColor Green "Execution completed in $($ElapsedTime.Hours):$($ElapsedTime.Minutes):$($ElapsedTime.Seconds)`n"
