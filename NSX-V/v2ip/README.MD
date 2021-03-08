# v2ip

A script that creates an IPSets for specified virtual machines, and places it into the effective NSX-v security group. It is designed to be used as part of a migration from NSX-v to NSX-T.

## Modes

The script operates in 2 modes, `prepare` and `replace`. It is done this way to allow the information to be gathered and validated, before any changes implemented.

### Mode: Prepare

In this mode the script requires an existing connection to vCenter and NSX Manager. The targeted virtual machines are supplied using the `-virtualmachine` parameter which accepts virtual machine objects, names or morefs (in the format of either `vm-xx` or `Virtual-Machine-vm-xx`). Required information is gathered from both vCenter and NSX Manager and is then saved in JSON format with the naming convention `<scriptName>_<vm name>_<vm id>_prepare.json`

The following parameters are available to run in this mode:

- `-mode Prepare`
  - Required parameter that tells the script to run in prepare mode
- `-VirtualMachine`
  - Required parameter used to supply one or more virtual machine names or Ids
- `-VmDuplicateName`
  - Option switch that instruct the script to continue processing the virtual machines, even if there are 2 virtual machines that match the same name as supplied. By default, the script will throw an error and terminate if it finds more than 1 match for a given virtual machine name.

### Mode: Replace

In this mode the script requires an existing connection to NSX Manager only. The `-file` parameter is used to specify the name/path to the JSON files created via the `prepare` mode. Each file is then processed, and an IPSet is created for each VM and added to all the effective security groups. At the completion, the IPSet information for the virtual machine and any vnics added to the original JSON data and saved into a new file with the naming convention `<scriptName>_<vm name>_<vm id>_complete.json`

The following parameters are available to run in this mode:

- `-mode Replace`
  - Required parameter that tells the script to run in replace mode
- `-file`
  - Required parameter used to supply 1 or more files to be processed. The files to be processed are the ones created from the `prepare` mode.
- `-IpSetPrefix`
  - Optional parameter to set the IPSet name prefix. If not specified, `MigratedVM` is used.
- `-IpAddressFamily`
  - Optional parameter to define the IP Address Family to use to create the IPSets. Options available are `v4`, `v6`, `both`. If not specified, `both` is used.

## Example: Prepare Mode

- Execute the script and supplying the VM Name

```Terminal
PS > .\v2ip.ps1 -mode prepare -VirtualMachine singlenicvm1

[16:48:05]: ================================================================================
[16:48:05]: Script version: 1.0.0
[16:48:05]: Script start time: 03/05/2021 16:48:05
[16:48:05]: Logging File: v2ip-2021-03-05-164805.log
[16:48:05]: Script mode: prepare
[16:48:05]: IpAddressFamily: both
[16:48:05]: AddressFamilies: v4 v6
[16:48:05]: ================================================================================
[16:48:05]: Retrieving virtual machines
[16:48:07]: ================================================================================
[16:48:07]: Retrieving NSX-v Security Groups
[16:48:10]: Retrieving NSX-v IPSets
[16:48:13]: Retrieving NSX-v SpoofguardPolicies
[16:48:16]: Retrieving NSX-v Spoofguard NIC details
[16:48:18]: --------------------------------------------------------------------------------
[16:48:18]: Processing VM: SingleNicVM1 (vm-48)
[16:48:22]: Persisting data to disk for VM SingleNicVM1 (vm-48) (v2ip_SingleNicVM1_vm-48_prepare.json)

[16:48:22]: Execution completed in 0:0:16
```

- The following file is then created: `v2ip_SingleNicVM1_vm-48_prepare.json`

```JSON
{
  "virtualMachine": {
    "moref": "vm-48",
    "DynamicCriteria": [
      {
        "objectId": "securitygroup-23",
        "dynamicMemberDefinition": "<dynamicMemberDefinition><dynamicSet><operator>OR</operator><dynamicCriteria><operator>OR</operator><key>ENTITY</key><criteria>belongs_to</criteria><value>vm-48</value><object><objectId>vm-48</objectId><objectTypeName>VirtualMachine</objectTypeName><vsmUuid>4206E278-9432-4960-A2DD-7A6FA3CB94C7</vsmUuid><nodeId>63148763-29b9-4e78-9999-4b6eaea560b6</nodeId><revision>3</revision><type><typeName>VirtualMachine</typeName></type><name>SingleNicVM1</name><scope><id>domain-c9</id><objectTypeName>ClusterComputeResource</objectTypeName><name>cluster-1</name></scope><clientHandle></clientHandle><extendedAttributes /><isUniversal>false</isUniversal><universalRevision>0</universalRevision><isTemporal>false</isTemporal></object><isValid>true</isValid></dynamicCriteria></dynamicSet></dynamicMemberDefinition>",
        "name": "SingleNicVmGroupDyn"
      }
    ],
    "name": "SingleNicVM1",
    "Exclude": [
      {
        "objectId": "securitygroup-22",
        "name": "SingleNicVmGroupExc"
      }
    ],
    "ipAddress": {
      "v4": [
        "10.10.128.100"
      ],
      "v6": [
        "0:0:0:0:0:ffff:a0a:8064"
      ]
    },
    "Include": [
      {
        "objectId": "securitygroup-21",
        "name": "SingleNicVMGroupInc"
      },
      {
        "objectId": "securitygroup-25",
        "name": "Consumer-Group-SC"
      }
    ],
    "tags": [
      {
        "objectId": "securitytag-4",
        "name": "IDS_IPS.threat=high"
      }
    ]
  },
  "virtualNic": {
    "503ec80a-f6eb-fcc1-b606-a813793e561a.000": {
      "Include": [],
      "Exclude": [],
      "ipAddress": {
        "v4": [
          "10.10.128.100"
        ],
        "v6": [
          "0:0:0:0:0:ffff:a0a:8064"
        ]
      },
      "DynamicCriteria": []
    }
  },
  "effectiveGroups": [
    {
      "objectId": "securitygroup-18",
      "name": "testSwitch"
    },
    {
      "objectId": "securitygroup-24",
      "name": "SingleNicVmGroupTag"
    },
    {
      "objectId": "securitygroup-25",
      "name": "Consumer-Group-SC"
    },
    {
      "objectId": "securitygroup-26",
      "name": "internal_security_group_for_Service-Composer-Policy-001"
    },
    {
      "objectId": "securitygroup-21",
      "name": "SingleNicVMGroupInc"
    },
    {
      "objectId": "securitygroup-23",
      "name": "SingleNicVmGroupDyn"
    }
  ]
}
```

## Example: Replace Mode

- Execute the script using the file: `v2ip_SingleNicVM1_vm-48_prepare.json`

```Terminal
PS C:\temp> .\v2ip.ps1 -mode replace -file .\v2ip_SingleNicVM1_vm-48_prepare.json

[16:54:28]: ================================================================================
[16:54:28]: Script version: 1.0.0
[16:54:28]: Script start time: 03/05/2021 16:54:28
[16:54:28]: Logging File: v2ip-2021-03-05-165428.log
[16:54:28]: Script mode: replace
[16:54:28]: IpAddressFamily: both
[16:54:28]: AddressFamilies: v4 v6
[16:54:28]: ================================================================================
[16:54:28]: Checking to see if files exist
[16:54:28]: ================================================================================
[16:54:28]: Retrieving NSX-v Security Groups
[16:54:31]: Retrieving NSX-v IPSets
[16:54:33]: Retrieving NSX-v SpoofguardPolicies
[16:54:37]: Retrieving NSX-v Spoofguard NIC details
[16:54:38]: --------------------------------------------------------------------------------
[16:54:38]: Processing VM: SingleNicVM1(vm-48)
[16:54:42]: Adding VM IPSet MigratedVM_v4_SingleNicVM1_vm-48 (ipset-24) to effective security group testSwitch (securitygroup-18)
[16:54:45]: Adding VM IPSet MigratedVM_v4_SingleNicVM1_vm-48 (ipset-24) to effective security group SingleNicVmGroupTag (securitygroup-24)
[16:54:47]: Adding VM IPSet MigratedVM_v4_SingleNicVM1_vm-48 (ipset-24) to effective security group Consumer-Group-SC (securitygroup-25)
[16:54:50]: Adding VM IPSet MigratedVM_v4_SingleNicVM1_vm-48 (ipset-24) to effective security group SingleNicVMGroupInc (securitygroup-21)
[16:54:55]: Adding VM IPSet MigratedVM_v4_SingleNicVM1_vm-48 (ipset-24) to effective security group SingleNicVmGroupDyn (securitygroup-23)
[16:55:01]: Adding VM IPSet MigratedVM_v6_SingleNicVM1_vm-48 (ipset-25) to effective security group testSwitch (securitygroup-18)
[16:55:04]: Adding VM IPSet MigratedVM_v6_SingleNicVM1_vm-48 (ipset-25) to effective security group SingleNicVmGroupTag (securitygroup-24)
[16:55:06]: Adding VM IPSet MigratedVM_v6_SingleNicVM1_vm-48 (ipset-25) to effective security group Consumer-Group-SC (securitygroup-25)
[16:55:09]: Adding VM IPSet MigratedVM_v6_SingleNicVM1_vm-48 (ipset-25) to effective security group SingleNicVMGroupInc (securitygroup-21)
[16:55:11]: Adding VM IPSet MigratedVM_v6_SingleNicVM1_vm-48 (ipset-25) to effective security group SingleNicVmGroupDyn (securitygroup-23)

[16:55:13]: Execution completed in 0:0:44
```

## Known Issues

- The script is currently only handling VM membership within security groups. If a VM is directly referenced in the source/destination of a DFW rule, the script will not have any affect. The scenario to determine if the VM is used directly in a DFW rule, and subsequently replace it with an IPSet will be addressed in a future update.
