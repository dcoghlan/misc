# Author: Dale Coghlan
# Email: dcoghlan@vmware.com
# Date: June 9th 2020

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
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string]$IpAddress
)

function IP-toINT64 () {
    param (
        [Parameter (Mandatory=$true, Position=1)]
        [string]$ip
    )

    $octets = $ip.split(".")
    return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3])
}

function INT64-toIP() {
    param ([int64]$int)

    return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )

}

function ConvertFrom-Bitmask {

    param (
        [Parameter(Mandatory=$true)]
            [ValidateRange(1,32)]
            [int]$Bitmask
    )

    # This was taken straight from PowerNSX, but doesn't work on Powershell Core Alpha18 correctly. There is no Address property on variable when cast to IP Address.
    # [ipaddress]$base = "255.255.255.255"
    # $invertedmask = [ipaddress]($base.address - [convert]::toint64(([math]::pow(2,(32-$bitmask)) -bxor $base.Address) + 1))

    # So this is a workaround
    $base = IP-toINT64 "255.255.255.255"
    $invertedmask = [ipaddress]($base - [convert]::toint64(([math]::pow(2,(32-$bitmask)) -bxor $base) + 1))
    [ipaddress]$subnetmask = "$(255-$($invertedmask.GetAddressBytes()[3]))." +
        "$(255-$($invertedmask.GetAddressBytes()[2]))." +
        "$(255-$($invertedmask.GetAddressBytes()[1]))." +
        "$(255-$($invertedmask.GetAddressBytes()[0]))"

    $subnetmask
}

function ConvertTo-Bitmask {

    param (
        [Parameter(Mandatory=$true)]
            [ipaddress]$subnetmask
    )

    $bitcount = 0
    $boundaryoctetfound = $false
    $boundarybitfound = $false
    #start at most sig end.
    foreach ($octet in $subnetmask.GetAddressBytes()) {

        switch ($octet) {
            "255" {
                if ( $boundaryoctetfound ) {
                    throw "SubnetMask specified is not valid.  Specify a valid mask and try again."
                } else {
                    $bitcount += 8
                }
            }

            "0" { $boundaryoctetfound = $true }

            default {
                if ( $boundaryoctetfound ) {
                    throw "SubnetMask specified is not valid.  Specify a valid mask and try again."
                }
                else {
                    $boundaryoctetfound = $true
                    $boundaryoctet = $_

                    for ( $i = 7; $i -ge 0 ; $i-- ) {
                        if ( $boundaryoctet -band [math]::pow(2,$i) ) {
                            if ( $boundarybitfound) {
                                # Already hit boundary - mask isnt valid.
                                throw "SubnetMask specified is not valid.  Specify a valid mask and try again."
                            }
                            $bitcount++
                        }
                        else {
                            $boundarybitfound = $true
                        }
                    }
                }
            }
        }
    }

    $bitcount
}

function Get-NetworkFromHostAddress {

    [CmdletBinding(DefaultParameterSetName="mask")]

    param (
        [Parameter(Mandatory=$true,ParameterSetName="cidr")]
        [Parameter(Mandatory=$true,ParameterSetName="mask")]
            [ipaddress]$Address,
        [Parameter(Mandatory=$true,ParameterSetName="mask")]
            [ipaddress]$SubnetMask,
        [Parameter(Mandatory=$true,ParameterSetName="cidr")]
            [ValidateRange(1,32)]
            [int]$BitMask

    )

    if ( $PsCmdlet.ParameterSetName -eq 'cidr') {
        $SubnetMask = convertfrom-bitmask -bitmask $BitMask
    }

    $NetAddress = ""
    for ( $i = 0; $i -le 3; $i++ ) {

        $NetAddress += "$($Address.GetAddressBytes()[$i] -band $SubnetMask.GetAddressBytes()[$i])."
    }
    [ipaddress]($NetAddress -replace "\.$","")
}

function Get-NetworkRange {

    [CmdletBinding(DefaultParameterSetName="mask")]
    param (
        [Parameter(Mandatory=$true,ParameterSetName="mask")]
            [ipaddress]$SubnetMask,
        [Parameter(Mandatory=$true,ParameterSetName="cidr")]
            [ValidateRange(1,32)]
            [int]$Bitmask,
        [Parameter(Mandatory=$true)]
            [ipaddress]$Network
    )

    if ( $PsCmdlet.ParameterSetName -eq 'cidr') {
        $SubnetMask = convertfrom-bitmask -bitmask $BitMask
    }
    if ( $PsCmdlet.ParameterSetName -eq 'mask') {
        $Bitmask = convertto-bitmask -subnetmask $SubnetMask
    }

    #Check that the network specified is a valid network address
    if ( -not (( Get-NetworkFromHostAddress -address $network -subnetmask $subnetmask ) -eq $network  )) {
        throw "Specified Network address is not valid (Does not lie on subnet boundary)"
    }

    $Range = New-Object System.Collections.Arraylist
    $CurrentAddress = $network

    $CurrAddressBytes = @( $Network.GetAddressBytes()[0], $Network.GetAddressBytes()[1], $Network.GetAddressBytes()[2], $Network.GetAddressBytes()[3])
    do {

        $CurrAddressBytes[3] += 1
        if ( $CurrAddressBytes[3] -eq 256 ) {
            $CurrAddressBytes[3] = 0
            $CurrAddressBytes[2] += 1

            if ( $CurrAddressBytes[2] -eq 256 ) {
                $CurrAddressBytes[2] = 0
                $CurrAddressBytes[1] + 1

                if ( $CurrAddressBytes[1] -eq 256 ) {
                    $CurrAddressBytes[1] = 0
                    $CurrAddressBytes[0] + 1

                    if ( $CurrAddressBytes[0] -eq 256 ) {
                        break
                    }
                }
            }
        }

        $currentaddress = "$($CurrAddressBytes[0]).$($CurrAddressBytes[1]).$($CurrAddressBytes[2]).$($CurrAddressBytes[3])"

    } while ( Test-AddressInNetwork -network $network -subnetmask $subnetmask -address $currentaddress )

    $broadcast = Get-BroadcastAddress -IPAddress $network -Bitmask $bitmask

    [pscustomobject]@{
        "NetworkAddress" = $network
        "ValidAddressRange" = $range
        "Broadcast" = $BroadCastAddress
        "Bitmask" = $Bitmask
        "SubnetMask" = $SubnetMask
    }
}

function Test-AddressInNetwork {

    [CmdletBinding(DefaultParameterSetName="mask")]
    param (
        [Parameter(Mandatory=$true,ParameterSetName="mask")]
            [ipaddress]$SubnetMask,
        [Parameter(Mandatory=$true,ParameterSetName="cidr")]
            [ValidateRange(1,32)]
            [int]$Bitmask,
        [Parameter(Mandatory=$true)]
            [ipaddress]$Network,
        [Parameter(Mandatory=$true)]
            [ipaddress]$Address
    )

    if ( $PsCmdlet.ParameterSetName -eq 'cidr') {
        $SubnetMask = convertfrom-bitmask -bitmask $BitMask
    }
    $Network -eq (Get-NetworkFromHostAddress -Address $Address -SubnetMask $SubnetMask)
}

function Get-BroadcastAddress{
    # Shamelessly stolen and modified from http://community.idera.com/powershell/powertips/b/tips/posts/calculate-broadcast-address
    param
    (
    [Parameter(Mandatory=$true)]
    $IPAddress,
    [Parameter(Mandatory=$true,ParameterSetName="cidr")]
        [ValidateRange(1,32)]
        [int]$Bitmask
    )

    $SubnetMask = convertfrom-bitmask -bitmask $BitMask

    [UInt32]$ip = IP-toINT64 $IPAddress
    [UInt32]$subnet = IP-toINT64 $SubnetMask
    [UInt32]$broadcast = $ip -band $subnet 
    $output = $broadcast -bor -bnot $subnet
    return INT64-toIP $output
}

$IpAddressObject = [ipaddress]"$ipaddress"
$ipAddressInteger = IP-toINT64 $IpAddressObject

Write-Host " --> Retrieving IP Sets"
$ipsets = Get-NsxIpSet
Write-host " --> Searching IP Sets for a match"
foreach ($ipset in $ipsets) {
    foreach ($value in ($ipset.value -split ',') ) {
        # Check if its an exact match
        if ( ($value -eq $IpAddressObject.toString()) -OR ($value -eq "$($IpAddressObject.toString())/32") ) {
            write-host -foregroundcolor green ("  --> $($ipset.name): $value")
        }
        # Check if supplied IP address is contained within a network in the IPSet
        elseif ($value -match '/') {
            $networkExploded = $value -split '/'
            $FoundInNetwork = Test-AddressInNetwork -address $IpAddressObject -Network $networkExploded[0] -bitmask $networkExploded[1]
            if ($FoundInNetwork) {
                write-host -foregroundcolor green ("  --> $($ipset.name): $value")
            }
        }
        # Check if supplied IP address is contained within a range in the IPSet
        elseif ($value -match '-') {
            $rangeExploded = $value -split '-'
            $rangeStartIp = $rangeExploded[0]
            $rangeEndIp = $rangeExploded[1]
            $rangeStartInteger = IP-toINT64 $rangeStartIp
            $rangeEndInteger = IP-toINT64 $rangeEndIp
            if ( ($IpAddressInteger -ge $rangeStartInteger) -AND ($IpAddressInteger -le $rangeEndInteger) ) {
                write-host -foregroundcolor green ("  --> $($ipset.name): $value")
            }
        }
    }
}