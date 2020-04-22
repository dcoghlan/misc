$dataHash = @{}

foreach ($vm in Get-VM) {
	$vmHash = @{
	    "name" = $vm.name;
		"uuid" = $vm.extensiondata.config.uuid;
		"instanceuuid" = $vm.extensiondata.config.instanceuuid;
	}
	$dataHash.Add($vm.extensiondata.moref.value, $vmHash)
}

$dataHash | Export-CliXML -path vmIds.xml
