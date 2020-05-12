# Add Virtual Machines to Pre-Created NSX-T Policy Groups

This script has been written with the purpose of being used as part of a suite of tools to help in the migration process from a NSX-v to NSX-T environment.

The script will process some pre-created desired state (Hierarchical API) policy json files which contain `virtualmachine/external_id` expressions, and add them to the relevant groups in NSX-T once the external_id of the VM is found in the NSX-T inventory.

The script requires the following inputs:

- NSX-T Manager IP/FQDN
- NSX-T Manager API Username
- NSX-T Manager API Password
- Path to the directory containing the pre-created desired state json files.

## Sample JSON File

``` json
{
  "resource_type": "Group",
  "display_name": "All Legacy Machines",
  "marked_for_delete": false,
  "expression": [
    {
      "member_type": "VirtualMachine",
      "resource_type": "ExternalIDExpression",
      "external_ids": [
        "5018eb82-2d36-d637-59d4-5a7bd01c76bd",
        "5023db4b-f567-4e6b-42e1-de7c781e20fe",
        "5018be9b-781d-e7ad-1fbc-4e8a630b29ed"
      ],
      "marked_for_delete": false
    }
  ],
  "id": "securitygroup-71"
}
```

## Example

``` bash
PS > ./add-vms-to-policy-groups.ps1 -NsxManager 192.168.172.28 -Username admin -password VMware1!VMware1! -JsonDirectory './jsonFiles/'


  --> Retrieving inventory virtual machines from NSX Manager
  --> Processing: securitygroup-71 (All Legacy Machines)...UPDATED (Some external_ids missing, check log file)

Execution completed in 0:0:2
LogFile: add-vms-to-policy-groups_2020-05-12-221026.log

```

The status next to each group being processed is as follows:

- SKIPPED = No changes made to the group, all the external_id/s specificed in the file were not visibile in the NSX-T inventory at the time the script was run.
- FAILED = An interaction with the NSX Manager failed. This will be because of failure to retrieve the group object, or patch the object. Check the log file for more information.
- OK = The specified external_ids already exists in the expression. If at least one is still missing as it wasn't found in the NSX-T inventory, it will display `OK (Some external_ids missing, check log file)`
- UPDATED = The object has been updated with at least 1 or more valid external_ids. If at least one is still missing as it wasn't found in the NSX-T inventory, it will display `OK (Some external_ids missing, check log file)`

It is safe to run the script multiple times.  If there are no changes to apply then nothing will be changed. It will only add VMs as it finds them. So it should be safe to continually run the script untill it reports all groups with a status of `OK`.

## LogFile Output

``` log
22:10:26 : add-vms-to-policy-groups.ps1: line 316, add-vms-to-policy-groups.ps1: INFO: --------------------------------------------------------------------------------
22:10:26 : add-vms-to-policy-groups.ps1: line 317, add-vms-to-policy-groups.ps1: INFO: Script start time = 05/12/2020 22:10:26
22:10:26 : add-vms-to-policy-groups.ps1: line 320, add-vms-to-policy-groups.ps1: VERBOSE: JsonDirectory = ./jsonFiles/
22:10:26 : add-vms-to-policy-groups.ps1: line 321, add-vms-to-policy-groups.ps1: VERBOSE: groupFileIdentifier = _group_
22:10:26 : add-vms-to-policy-groups.ps1: line 322, add-vms-to-policy-groups.ps1: VERBOSE: NSX Manager = 192.168.172.28
22:10:26 : add-vms-to-policy-groups.ps1: line 323, add-vms-to-policy-groups.ps1: VERBOSE: NSX Manager Username = admin
22:10:26 : add-vms-to-policy-groups.ps1: line 324, add-vms-to-policy-groups.ps1: VERBOSE: Powershell Edition: Core
22:10:26 : add-vms-to-policy-groups.ps1: line 325, add-vms-to-policy-groups.ps1: VERBOSE: Powershell Version: 7.0.0
22:10:26 : add-vms-to-policy-groups.ps1: line 326, add-vms-to-policy-groups.ps1: VERBOSE: Powershell OS: Darwin 19.4.0 Darwin Kernel Version 19.4.0: Wed Mar  4 22:28:40 PST 2020; root:xnu-6153.101.6~15/RELEASE_X86_64
22:10:26 : add-vms-to-policy-groups.ps1: line 327, add-vms-to-policy-groups.ps1: VERBOSE: Powershell Platform: Unix
22:10:27 : add-vms-to-policy-groups.ps1: line 371, add-vms-to-policy-groups.ps1: INFO: --------------------------------------------------------------------------------
22:10:27 : add-vms-to-policy-groups.ps1: line 372, add-vms-to-policy-groups.ps1: VERBOSE: Loading _group_ file: SAMPLE_group_All Legacy Machines.json
22:10:27 : add-vms-to-policy-groups.ps1: line 376, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: Processing group: All Legacy Machines
22:10:27 : add-vms-to-policy-groups.ps1: line 377, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: Total Expressions found = 1
22:10:27 : add-vms-to-policy-groups.ps1: line 383, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: Processing external_id found in _group_ file: 5018eb82-2d36-d637-59d4-5a7bd01c76bd
22:10:27 : add-vms-to-policy-groups.ps1: line 386, add-vms-to-policy-groups.ps1: ERROR: securitygroup-71: External_id not found in NSX-T Inventory: 5018eb82-2d36-d637-59d4-5a7bd01c76bd
22:10:27 : add-vms-to-policy-groups.ps1: line 383, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: Processing external_id found in _group_ file: 5023db4b-f567-4e6b-42e1-de7c781e20fe
22:10:27 : add-vms-to-policy-groups.ps1: line 391, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: Found matching external_id in NSX-T Inventory: 5023db4b-f567-4e6b-42e1-de7c781e20fe (DR-App-01)
22:10:27 : add-vms-to-policy-groups.ps1: line 383, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: Processing external_id found in _group_ file: 5018be9b-781d-e7ad-1fbc-4e8a630b29ed
22:10:27 : add-vms-to-policy-groups.ps1: line 386, add-vms-to-policy-groups.ps1: ERROR: securitygroup-71: External_id not found in NSX-T Inventory: 5018be9b-781d-e7ad-1fbc-4e8a630b29ed
22:10:27 : add-vms-to-policy-groups.ps1: line 402, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: Additional external_ids to add = 1
22:10:27 : add-vms-to-policy-groups.ps1: line 404, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: Retrieving group configuration
22:10:28 : add-vms-to-policy-groups.ps1: line 436, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: No existing VirtualMachine/ExternalIDExpression found
22:10:28 : add-vms-to-policy-groups.ps1: line 441, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: Adding Conjunction with OR operator
22:10:28 : add-vms-to-policy-groups.ps1: line 446, add-vms-to-policy-groups.ps1: VERBOSE: securitygroup-71: Adding new VirtualMachine/ExternalIDExpression
22:10:28 : add-vms-to-policy-groups.ps1: line 456, add-vms-to-policy-groups.ps1: INFO: securitygroup-71: Patching updated configuration
22:10:29 : add-vms-to-policy-groups.ps1: line 492, add-vms-to-policy-groups.ps1: INFO: Script duration = 00:00:03.4010980
```
