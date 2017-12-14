$vmlist = Get-NsxApplicableMember -SecurityGroupApplicableMembers -MemberType VirtualMachine
ForEach ($vm in $vmlist) {
    $AddressArray = new-object system.collections.arrayList
    $URI = "/api/2.0/services/securitygroup/$($vm.objectid)/translation/ipaddresses"
    $response = invoke-nsxwebrequest -method GET -uri $URI
    [system.xml.xmldocument]$data = $response.content
    [system.collections.arraylist]$ips = $data.ipNodes.ipNode.ipAddresses.string -split ","

    ForEach ($ip in $ips) {
        $ipobject = [ipaddress]$ip
        if ($ipobject.AddressFamily -eq "InterNetwork") {
            $AddressArray.Add($ip.tostring()) | out-null
        }
    }
    write-host "  -> Creating IP Set for $($vm.name) with ip address $(($AddressArray -join ","))"
    New-NsxIpSet -Name $vm.name -IPAddress $AddressArray -Universal -ReturnObjectIdOnly | out-null
}
