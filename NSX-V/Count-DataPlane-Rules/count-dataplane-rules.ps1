# Author: Dale Coghlan
# Email: dcoghlan@vmware.com
# Date: June 9th 2020

param (
    [parameter(Mandatory = $True, ParameterSetName="AllRules")]
    [parameter(Mandatory = $True, ParameterSetName="Section")]
    [parameter(Mandatory = $True, ParameterSetName="RuleId")]
    [ValidateNotNullOrEmpty()]
    [string]$Username,
    [parameter(Mandatory = $True, ParameterSetName="AllRules")]
    [parameter(Mandatory = $True, ParameterSetName="Section")]
    [parameter(Mandatory = $True, ParameterSetName="RuleId")]
    [ValidateNotNullOrEmpty()]
    [string]$Password,
    [parameter(Mandatory = $True, ParameterSetName="AllRules")]
    [parameter(Mandatory = $True, ParameterSetName="Section")]
    [parameter(Mandatory = $True, ParameterSetName="RuleId")]
    [ValidateNotNullOrEmpty()]
    [string]$Server,
    [parameter(Mandatory = $False, ParameterSetName="AllRules")]
    [parameter(Mandatory = $False, ParameterSetName="Section")]
    [parameter(Mandatory = $False, ParameterSetName="RuleId")]
    [ValidateNotNullOrEmpty()]
    [string]$Environment,
    [parameter(Mandatory = $True, ParameterSetName="AllRules")]
    [parameter(Mandatory = $True, ParameterSetName="Section")]
    [parameter(Mandatory = $True, ParameterSetName="RuleId")]
    # All filters attached to the VM will be analysed.
    [ValidateNotNullOrEmpty()]
    [string]$VmName,
    [parameter(Mandatory = $True, ParameterSetName="Section")]
    # Distributed Firewall section name. All rules found in the given section will be processed.
    [ValidateNotNullOrEmpty()]
    [string]$SectionName,
    [parameter(Mandatory = $True, ParameterSetName="RuleId")]
    # Distributed Firewall section name. All rules found in the given section will be processed.
    [ValidateNotNullOrEmpty()]
    [string[]]$RuleId
)

$StartTime = Get-Date
$Prefix = $StartTime.ToString('yyy-MM-dd-HHmmss')

# Add an environment prefix to the file names if provided
if ($PSBoundParameters.ContainsKey('Environment')) {
    $Prefix = "$Environment-$Prefix"
}

# Initialise some variables
$ruleIdsList = New-Object System.Collections.ArrayList
$data = New-Object System.Collections.ArrayList
$outputFile = "$Prefix-details.csv"
$outputFileLog = "$Prefix-log.txt"
$ruleCounterTable = [ordered]@{}

Write-Host "`n$("-"*80)"
Write-Host "`n  Script Mode: $($PSCmdlet.ParameterSetName)"
Write-Host "  Logging File: $outputFileLog"
Write-Host "  Rule Details: $outputFile`n"
Write-Host "$("-"*80)`n"

# Make sure we connect to the NSX Manager provided
if (-not ($global:DefaultNsxConnection)) {
    Write-Host " --> Establishing a PowerNSX connection to $server"
    Connect-NsxServer -Server $Server -Username $Username -Password $Password -DisableVIAutoConnect -WarningAction SilentlyContinue | Out-Null
}
else {
    Write-host " --> Found existing PowerNSX connection: ($($Global:DefaultNSXConnection.Server))"
    Write-host " --> Disconnecting from NSX Manager: ($($Global:DefaultNSXConnection.Server))"
    Disconnect-NsxServer
    Write-Host " --> Establishing new PowerNSX connection to $server"
    Connect-NsxServer -Server $Server -Username $Username -Password $Password -DisableVIAutoConnect -WarningAction SilentlyContinue | Out-Null
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

if ($PSCmdlet.ParameterSetName -eq 'RuleId') {
    foreach ($id in $RuleId) {
        $ruleIdsList.Add($id) | Out-Null
    }
} else {
    if ($PSCmdlet.ParameterSetName -eq 'Section') {
        Write-host " --> Retrieving rule ids from section: $SectionName... " -NoNewline
    }
    else {
        Write-host " --> Retrieving rule ids from all sections... " -NoNewline
    }
    # Use the SectionName to find all the ruleIds in the section, or
    # from all sections if no section was supplied
    try {
        $validSectionFound = $False
        $sectionTypes = "layer3sections", "layer3redirectsections", "layer2sections"
        foreach ($sectionType in $sectionTypes) {
            $dfwSection = Get-NsxFirewallSection -Name $SectionName -sectionType $sectionType
            if ($dfwSection) {
                $validSectionFound = $True
                $dfwSectionRuleIds = $dfwSection | get-NsxFirewallRule | Select-Object id
                if ($dfwSectionRuleIds) {
                    $validRulesFound = $True
                }
            }

            if (!$validRulesFound) {
                Write-Log -Level Debug -Msg ("Error: No rules found in section $SectionName")
                Write-host -ForegroundColor Red "Failed"
                exit
            }
            else {
                foreach ($ruleid in $dfwSectionRuleIds.id) {
                    $ruleIdsList.Add($ruleid) | Out-Null
                }
            }
        }
        Write-Log -Level Debug -Msg ("RuleIds: $($ruleIdsList | Format-Table | Out-String)")
        Write-host -ForegroundColor Green "OK"
    }
    catch {
        Write-Log -Level Debug -Msg ("Error: $_")
        Write-host -ForegroundColor Red "Failed"
        exit
    }
}

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
# summarize-dvfilter command on each host to find the appropriate VM and 
# process its configured filters.

foreach ($cluster in ($dfwClusters | Where-Object { ($_.'Firewall Status' -eq "Enabled") -AND ($_.'Firewall Fabric Status' -eq "Green")} ) ) {

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
        if (($summarizeDvfilterOutput -split "`n") -match '(?<=vmm0:)' + $VmName + '(?= vcUuid:)') {
            $VmNameMatch = $False
            $filtersToCheck = New-Object System.Collections.ArrayList
            foreach ( $line in ($summarizeDvfilterOutput -split "`n") ) {
                if ($line -match '(?<=vmm0:)(.*)(?= vcUuid:)' ) {
                    if ($matches[0] -eq $VmName) {
                        Write-Log -Level Debug -Msg "Found virtual machine dvFilter match for $VmName"
                        $VmNameMatch = $True
                        continue
                    } else {
                        $VmNameMatch = $False
                    }
                }
                if ( ( $line -match '(?<=name:\s+)(.*\.([2,4-9]|1[0-5]))$') -AND ($VmNameMatch -eq $True) ) {
                    Write-Log -Level Debug -Msg "Adding dvFilter ($($matches[0])) to list of filters to check."
                    $filterName = $matches[0]
                    $filtersToCheck.Add($filterName) | Out-Null
                }
            }
            Write-Log -Level Debug -Msg "FiltersToCheck: $($filtersToCheck | Out-String) "
            Write-Log -Level Debug -Msg "Found VM Nic on host $dfwHost"
            $ruleCount = 0
            foreach ($filterNameToCheck in $filtersToCheck) {
                $queryDfwFilterRules = "show dfw host $($dfwHost.'Host Id') filter $filterNameToCheck rules"
                Write-Log -Level Debug -Msg "Executing: $queryDfwFilterRules"
                $filterRulesOutput = Invoke-Nsxcli -query $queryDfwFilterRules -RawOutput -WarningAction SilentlyContinue
                Add-Content -path "$Prefix-$filterNameToCheck.txt" -Value $filterRulesOutput
                foreach ($filterLine in ($filterRulesOutput -split "`n") ) {
                    Write-Log -Level Debug -Msg "processing: $filterline"
                    if ($filterLine -match '(?<=.*\s+rule\s+)(\d+)(?=\s+at\s+.*;)') {
                        if ($ruleIdsList | ? {$_ -eq $matches[0]}) {
                            if ($ruleCounterTable.Contains($matches[0])) {
                                $ruleCounterTable.item($matches[0]) = [int]$ruleCounterTable.item($matches[0]) + 1
                            }
                            else {
                                $ruleCounterTable.Add($matches[0], 1)
                            }
                            $ruleCount += 1
                        }
                    }
                }
            }
            $ruleCounterTable.Add("Total", $ruleCount)
        }
    }
}

# Add header row to csv output file
Add-Content -path $outputFile -value ("RuleId,RuleCount")

# Add the data from the hashtable into the CSV file
foreach ($key in $ruleCounterTable.keys) {
    Add-Content -path $outputFile -value ("$key, $($ruleCounterTable.item($key))")
}

$ElapsedTime = $((get-date) - $StartTime)
write-host -foregroundcolor Green "`nExecution completed in $($ElapsedTime.Hours):$($ElapsedTime.Minutes):$($ElapsedTime.Seconds)`n"

