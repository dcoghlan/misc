# Tagging NSX-T VMs from a PowerNSX Object Capture

Script that will tag NSX-T inventory virtual machines with the same NSX-v Security Tags once the virtual machine appears in the NSX-T Inventory. 

The script requires the following inputs:

- NSX-T Manager IP/FQDN
- NSX-T Manager API Username
- NSX-T Manager API Password
- `VmExport.xml` from a PowerNSX Object-Capture taken from the NSX-v environment where the virtual machines and NSX Security Tags are coming from. The script to gather the PowerNSX Object-Capture can be found at <https://github.com/vmware/powernsx/blob/master/tools/DiagramNSX/NsxObjectCapture.ps1>
The script requireds 
- `SecurityTagAssignmentByVmExport.xml` as created from the following PowerNSX script <https://github.com/dcoghlan/misc/blob/master/NSX-V/Capture-Nsx-Tag-Assignment/capture-nsx-tag-assignment.ps1>

## Example

``` bash
PS > ./tag-vms-from-capture.ps1 -NsxManager 192.168.172.28 -Username admin -Password VMware1!VMware1!  -VmExportFile './NSX-ObjectCapture-10.61.186.60-2020_05_06_14_11_59/VmExport.xml' -TagAssignmentByVmFile './SecurityTagAssignmentByVmExport.xml'

  --> Retrieving inventory virtual machines from NSX Manager
  --> Processing: 5023c611-f5b3-1392-fc0b-e69194703563...SKIPPED
  --> Processing: 5023db4b-f567-4e6b-42e1-de7c781e20fe...SKIPPED
  --> Processing: 5023e349-7452-7dfc-54d5-b45078bf399b...FAILED
  --> Processing: 502329ad-ec60-5767-d6e1-0cc2861bb345...SKIPPED
  --> Processing: 502338c8-a84a-daa6-e625-b2c09b242c38...OK
  --> Processing: 502349b4-3b9f-0712-95c7-c26c1b936535...SKIPPED
  --> Processing: 50239513-4784-a71d-6cf8-122e8b33e730...UPDATED

Execution completed in 0:0:3
LogFile: tag-vms-from-capture_2020-05-11-112745.log 
```

The status next to each inventory virtual machine `external_id` is as follows:

- OK: The tag/s already exists on the virtual machine
- UPDATED: The tag/s have been added to the virtual machine
- SKIPPED: The NSX-T inventory virtual machine `external_id` is unable to be matched to a MoRef via a `instanceuuid` or `uuid`. This generally means that the VM is not in the file `VmExport.xml` which was part of the PowerNSX Object Capture, or there are no NSX-v Security Tags applied to the virtual machine, as per the `SecurityTagAssignmentByVmExport.xml` file.
- FAILED: There was an issue when attempting to update the tags on NSX Manager.

Detailed logging can be found in the log file.

## Logfile Output

``` log
09:52:17 : tag-vms-from-capture.ps1: line 132, Start-Log: DEBUG: New Logfile created as OverwriteLogFile was enabled.
09:52:17 : tag-vms-from-capture.ps1: line 284, tag-vms-from-capture.ps1: VERBOSE: VmExportFile = ./NSX-ObjectCapture-10.61.186.60-2020_05_06_14_11_59/VmExport.xml
09:52:17 : tag-vms-from-capture.ps1: line 285, tag-vms-from-capture.ps1: VERBOSE: TagAssignmentByVmFile = ./SecurityTagAssignmentByVmExport.xml
09:52:17 : tag-vms-from-capture.ps1: line 286, tag-vms-from-capture.ps1: VERBOSE: NSX Manager = 192.168.172.28
09:52:17 : tag-vms-from-capture.ps1: line 287, tag-vms-from-capture.ps1: VERBOSE: NSX Manager Username = admin
09:52:17 : tag-vms-from-capture.ps1: line 288, tag-vms-from-capture.ps1: VERBOSE: Powershell Edition: Core
09:52:17 : tag-vms-from-capture.ps1: line 289, tag-vms-from-capture.ps1: VERBOSE: Powershell Version: 7.0.0
09:52:17 : tag-vms-from-capture.ps1: line 290, tag-vms-from-capture.ps1: VERBOSE: Powershell OS: Darwin 19.4.0 Darwin Kernel Version 19.4.0: Wed Mar  4 22:28:40 PST 2020; root:xnu-6153.101.6~15/RELEASE_X86_64
09:52:17 : tag-vms-from-capture.ps1: line 291, tag-vms-from-capture.ps1: VERBOSE: Powershell Platform: Unix
09:52:19 : tag-vms-from-capture.ps1: line 323, tag-vms-from-capture.ps1: INFO: --------------------------------------------------------------------------------
09:52:19 : tag-vms-from-capture.ps1: line 325, tag-vms-from-capture.ps1: VERBOSE: 5023c611-f5b3-1392-fc0b-e69194703563: Processing VM: VMMVW01
09:52:19 : tag-vms-from-capture.ps1: line 326, tag-vms-from-capture.ps1: VERBOSE: 5023c611-f5b3-1392-fc0b-e69194703563: Existing Tag count: 0
09:52:19 : tag-vms-from-capture.ps1: line 334, tag-vms-from-capture.ps1: VERBOSE: 5023c611-f5b3-1392-fc0b-e69194703563: Moref = vm-1668
09:52:19 : tag-vms-from-capture.ps1: line 340, tag-vms-from-capture.ps1: VERBOSE: 5023c611-f5b3-1392-fc0b-e69194703563: No NSX-v Security Tags assigned
09:52:19 : tag-vms-from-capture.ps1: line 323, tag-vms-from-capture.ps1: INFO: --------------------------------------------------------------------------------
09:52:19 : tag-vms-from-capture.ps1: line 325, tag-vms-from-capture.ps1: VERBOSE: 5023db4b-f567-4e6b-42e1-de7c781e20fe: Processing VM: DR-App-01
09:52:19 : tag-vms-from-capture.ps1: line 326, tag-vms-from-capture.ps1: VERBOSE: 5023db4b-f567-4e6b-42e1-de7c781e20fe: Existing Tag count: 4
09:52:19 : tag-vms-from-capture.ps1: line 331, tag-vms-from-capture.ps1: VERBOSE: 5023db4b-f567-4e6b-42e1-de7c781e20fe: Skipping VM. No matching VM MoRef found.
09:52:19 : tag-vms-from-capture.ps1: line 323, tag-vms-from-capture.ps1: INFO: --------------------------------------------------------------------------------
09:52:19 : tag-vms-from-capture.ps1: line 325, tag-vms-from-capture.ps1: VERBOSE: 5023e349-7452-7dfc-54d5-b45078bf399b: Processing VM: DR-App-02
09:52:19 : tag-vms-from-capture.ps1: line 326, tag-vms-from-capture.ps1: VERBOSE: 5023e349-7452-7dfc-54d5-b45078bf399b: Existing Tag count: 1
09:52:19 : tag-vms-from-capture.ps1: line 334, tag-vms-from-capture.ps1: VERBOSE: 5023e349-7452-7dfc-54d5-b45078bf399b: Moref = vm-452
09:52:19 : tag-vms-from-capture.ps1: line 351, tag-vms-from-capture.ps1: VERBOSE: 5023e349-7452-7dfc-54d5-b45078bf399b: Processing NSX-v tag (tag_crm_app_dr)
09:52:19 : tag-vms-from-capture.ps1: line 353, tag-vms-from-capture.ps1: VERBOSE: 5023e349-7452-7dfc-54d5-b45078bf399b: NSX-v tag (tag_crm_app_dr) not configured
09:52:19 : tag-vms-from-capture.ps1: line 358, tag-vms-from-capture.ps1: VERBOSE: 5023e349-7452-7dfc-54d5-b45078bf399b: Adding tag (tag_crm_app_dr) to list of tags to add to vm
09:52:19 : tag-vms-from-capture.ps1: line 367, tag-vms-from-capture.ps1: VERBOSE: 5023e349-7452-7dfc-54d5-b45078bf399b: Found 1 tags to add
09:52:19 : tag-vms-from-capture.ps1: line 378, tag-vms-from-capture.ps1: VERBOSE: 5023e349-7452-7dfc-54d5-b45078bf399b: Updated tag count = 2
09:52:20 : tag-vms-from-capture.ps1: line 383, tag-vms-from-capture.ps1: ERROR: 5023e349-7452-7dfc-54d5-b45078bf399b: Failed to update tags on inventory virtual machine.
09:52:20 : tag-vms-from-capture.ps1: line 384, tag-vms-from-capture.ps1: ERROR: 5023e349-7452-7dfc-54d5-b45078bf399b: Tags to apply = [{"scope":"","tag":"existing_tag"},{"scope":"","tag":"tag_crm_app_dr"}]
09:52:20 : tag-vms-from-capture.ps1: line 385, tag-vms-from-capture.ps1: ERROR: {
    "module_name" : "common-services",
    "error_message" : "The requested with given URI, HTTP method and set of parameters cannot be processed.",
    "error_code" : "269"
}

09:52:20 : tag-vms-from-capture.ps1: line 323, tag-vms-from-capture.ps1: INFO: --------------------------------------------------------------------------------
09:52:20 : tag-vms-from-capture.ps1: line 325, tag-vms-from-capture.ps1: VERBOSE: 502329ad-ec60-5767-d6e1-0cc2861bb345: Processing VM: DR-Web-01
09:52:20 : tag-vms-from-capture.ps1: line 326, tag-vms-from-capture.ps1: VERBOSE: 502329ad-ec60-5767-d6e1-0cc2861bb345: Existing Tag count: 2
09:52:20 : tag-vms-from-capture.ps1: line 334, tag-vms-from-capture.ps1: VERBOSE: 502329ad-ec60-5767-d6e1-0cc2861bb345: Moref = vm-121040
09:52:20 : tag-vms-from-capture.ps1: line 340, tag-vms-from-capture.ps1: VERBOSE: 502329ad-ec60-5767-d6e1-0cc2861bb345: No NSX-v Security Tags assigned
09:52:20 : tag-vms-from-capture.ps1: line 323, tag-vms-from-capture.ps1: INFO: --------------------------------------------------------------------------------
09:52:20 : tag-vms-from-capture.ps1: line 325, tag-vms-from-capture.ps1: VERBOSE: 502338c8-a84a-daa6-e625-b2c09b242c38: Processing VM: DR-Web-02
09:52:20 : tag-vms-from-capture.ps1: line 326, tag-vms-from-capture.ps1: VERBOSE: 502338c8-a84a-daa6-e625-b2c09b242c38: Existing Tag count: 3
09:52:20 : tag-vms-from-capture.ps1: line 334, tag-vms-from-capture.ps1: VERBOSE: 502338c8-a84a-daa6-e625-b2c09b242c38: Moref = vm-87
09:52:20 : tag-vms-from-capture.ps1: line 351, tag-vms-from-capture.ps1: VERBOSE: 502338c8-a84a-daa6-e625-b2c09b242c38: Processing NSX-v tag (tag_antivirus_server)
09:52:20 : tag-vms-from-capture.ps1: line 362, tag-vms-from-capture.ps1: VERBOSE: 502338c8-a84a-daa6-e625-b2c09b242c38: Tag (tag_antivirus_server) already exists
09:52:20 : tag-vms-from-capture.ps1: line 323, tag-vms-from-capture.ps1: INFO: --------------------------------------------------------------------------------
09:52:20 : tag-vms-from-capture.ps1: line 325, tag-vms-from-capture.ps1: VERBOSE: 502349b4-3b9f-0712-95c7-c26c1b936535: Processing VM: DR-Web-03
09:52:20 : tag-vms-from-capture.ps1: line 326, tag-vms-from-capture.ps1: VERBOSE: 502349b4-3b9f-0712-95c7-c26c1b936535: Existing Tag count: 2
09:52:20 : tag-vms-from-capture.ps1: line 331, tag-vms-from-capture.ps1: VERBOSE: 502349b4-3b9f-0712-95c7-c26c1b936535: Skipping VM. No matching VM MoRef found.
09:52:20 : tag-vms-from-capture.ps1: line 323, tag-vms-from-capture.ps1: INFO: --------------------------------------------------------------------------------
09:52:20 : tag-vms-from-capture.ps1: line 325, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: Processing VM: Test-Mgmt-01
09:52:20 : tag-vms-from-capture.ps1: line 326, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: Existing Tag count: 1
09:52:20 : tag-vms-from-capture.ps1: line 334, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: Moref = vm-89
09:52:20 : tag-vms-from-capture.ps1: line 351, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: Processing NSX-v tag (tag_active_directory)
09:52:20 : tag-vms-from-capture.ps1: line 362, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: Tag (tag_active_directory) already exists
09:52:20 : tag-vms-from-capture.ps1: line 351, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: Processing NSX-v tag (tag_backup_to_tape)
09:52:20 : tag-vms-from-capture.ps1: line 362, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: NSX-v tag (tag_backup_to_tape) not configured
09:52:20 : tag-vms-from-capture.ps1: line 362, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: Adding tag (tag_backup_to_tape) to list of tags to add to vm
09:52:20 : tag-vms-from-capture.ps1: line 362, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: Found 1 tags to add
09:52:20 : tag-vms-from-capture.ps1: line 362, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: Updated tag count = 2
09:52:20 : tag-vms-from-capture.ps1: line 362, tag-vms-from-capture.ps1: VERBOSE: 50239513-4784-a71d-6cf8-122e8b33e730: Applying updated tags to inventory virtual machine

```