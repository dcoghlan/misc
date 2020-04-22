
$SecurityTagAssignmentByTagHash = @{}
$SecurityTagAssignmentByVmHash = @{}

foreach ($tag in (Get-NsxSecurityTag)) {
	if ($tag.objectid -notcontains $SecurityTagAssignmentByTagHash.keys) {
	    $SecurityTagAssignmentByTagHash[$tag.objectid] = New-Object System.Collections.ArrayList
	}
	
    foreach ($assignment in ($tag | Get-NsxSecurityTagAssignment) ) {
		if ($SecurityTagAssignmentByTagHash.keys -notcontains $assignment.securitytag.objectid) {
		    $SecurityTagAssignmentByTagHash[$assignment.securitytag.objectid] = New-Object System.Collections.ArrayList
		}
		
		if ($SecurityTagAssignmentByVmHash.keys -notcontains $assignment.virtualmachine.extensiondata.moref.value) {
		$SecurityTagAssignmentByVmHash[$assignment.virtualmachine.extensiondata.moref.value] = New-Object System.Collections.ArrayList
		}

		$vmHash = @{
		    "moref" = $assignment.virtualmachine.extensiondata.moref.value;
    	    "name" = $assignment.virtualmachine.name;
	    	"uuid" = $assignment.virtualmachine.extensiondata.config.uuid;
		    "instanceuuid" = $assignment.virtualmachine.extensiondata.config.instanceuuid;
		}

		$tagHash = @{
			"objectid" = $assignment.securitytag.objectid;
			"name" = $assignment.securitytag.name;
			"description" = $assignment.securitytag.description;
		}
	    $SecurityTagAssignmentByTagHash[$assignment.securitytag.objectid].Add($vmHash) | Out-Null
	    $SecurityTagAssignmentByVmHash[$assignment.virtualmachine.extensiondata.moref.value].Add($tagHash) | Out-Null		
		
	}
}
$SecurityTagAssignmentByTagHash | Export-CliXML -path SecurityTagAssignmentByTagExport.xml
$SecurityTagAssignmentByVmHash | Export-CliXML -path SecurityTagAssignmentByVmExport.xml
