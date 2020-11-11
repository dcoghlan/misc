# Remove temporary IP address from a segment wrapper group

This script has been written with the purpose of being used as part of a suite of tools to help in the migration process from a NSX-v to NSX-T environment.

In an NSX-v configuration, it was perfectly acceptable to use a logical switch directly in the source, destination or AppliedTo field of a firewall rule, however, when looking to translate the same configuration into NSX-T, the only objects available to use in the source, destination or AppliedTo field are a group.

This requires that when translating a configuration into NSX-T where a logical switch was directly used, a wrapper group containing the NSX-T segment should be created. To help with a staged migration, it's also advisable to add the CIDR address block into the NSX-T group so that any use of the object in a rule will not be dependant on having all the virtual machines migrated to their respective segments.

The purpose of this script is to go through and remove the CIDR address block from a given NSX-T segment wrapper group once all the virtual machines on a given segment have been migrated.

For the script to operate correctly, the segments and groups should be configured as follows:

- the segment wrapper group must be configured with the same `id` as the segment it is representing (must be identical in case)
- the segment wrapper group must have a tag containing the CIDR address block that has been added as an IpExpression.
- the scope for the tag on the segment wrapper group must be configured and uniquely identifiable.

The script requires the following inputs:

- NSX-T Manager IP/FQDN
- NSX-T Manager API Username
- NSX-T Manager API Password
- The complete segment path (e.g. `/infra/segments/v12343_nsx_prod_net_internal`)
- The tag scope to identify the tag containing the CIDR address block to be removed from the group (e.g. `migration/tempIp`)

## Example

```bash
PS > ./remove-temp-segment-groups.ps1.ps1 -NsxManager 192.168.172.27 -Username admin -password VMware1!VMware1! -SegmentPath /infra/segments/v12343_nsx_prod_net_internal  -MigrationTagScope migration/tempIp


  --> Validating segment path exists...OK
  --> Validating segment wrapper group exists...OK
  --> Validating segment wrapper group migration tag exists...OK
  --> Updating NSX Manager (192.168.172.27)...OK

Execution completed in 0:0:5
LogFile: remove-temp-segment-groups_2020-11-11-163309.log
```

## LogFile Output

```log
16:33:09 : remove-temp-segment-groups.ps1: line 271, remove-temp-segment-groups.ps1: INFO: --------------------------------------------------------------------------------
16:33:09 : remove-temp-segment-groups.ps1: line 272, remove-temp-segment-groups.ps1: VERBOSE: Script start time = 11/11/2020 16:33:09
16:33:09 : remove-temp-segment-groups.ps1: line 275, remove-temp-segment-groups.ps1: VERBOSE: SegmentPath = /infra/segments/v12343_nsx_prod_net_internal
16:33:09 : remove-temp-segment-groups.ps1: line 276, remove-temp-segment-groups.ps1: VERBOSE: MigrationTagScope = migration/tempIp
16:33:09 : remove-temp-segment-groups.ps1: line 277, remove-temp-segment-groups.ps1: VERBOSE: NSX Manager = 192.168.172.27
16:33:09 : remove-temp-segment-groups.ps1: line 278, remove-temp-segment-groups.ps1: VERBOSE: NSX Manager Username = admin
16:33:09 : remove-temp-segment-groups.ps1: line 279, remove-temp-segment-groups.ps1: VERBOSE: Powershell Edition: Core
16:33:09 : remove-temp-segment-groups.ps1: line 280, remove-temp-segment-groups.ps1: VERBOSE: Powershell Version: 7.0.3
16:33:09 : remove-temp-segment-groups.ps1: line 281, remove-temp-segment-groups.ps1: VERBOSE: Powershell OS: Darwin 19.6.0 Darwin Kernel Version 19.6.0: Thu Oct 29 22:56:45 PDT 2020; root:xnu-6153.141.2.2~1/RELEASE_X86_64
16:33:09 : remove-temp-segment-groups.ps1: line 282, remove-temp-segment-groups.ps1: VERBOSE: Powershell Platform: Unix
16:33:09 : remove-temp-segment-groups.ps1: line 297, remove-temp-segment-groups.ps1: INFO: --------------------------------------------------------------------------------
16:33:11 : remove-temp-segment-groups.ps1: line 302, remove-temp-segment-groups.ps1: VERBOSE: segmentDetails received via API.
{
  "type": "DISCONNECTED",
  "vlan_ids": [
    "2933"
  ],
  "transport_zone_path": "/infra/sites/default/enforcement-points/default/transport-zones/a95c914d-748d-497c-94ab-10d4647daeba",
  "admin_state": "UP",
  "replication_mode": "MTEP",
  "resource_type": "Segment",
  "id": "v12343_nsx_prod_net_internal",
  "display_name": "v12343_nsx_prod_net_internal",
  "description": "10.10.11.0/24",
  "tags": [
    {
      "scope": "migration/portprofile",
      "tag": "ESX01-HTC_PREP_EXT"
    }
  ],
  "path": "/infra/segments/v12343_nsx_prod_net_internal",
  "relative_path": "v12343_nsx_prod_net_internal",
  "parent_path": "/infra",
  "unique_id": "c2009890-9883-4f74-9ba5-c90d9749e1cf",
  "marked_for_delete": false,
  "overridden": false,
  "_system_owned": false,
  "_create_user": "admin",
  "_create_time": 1603876242546,
  "_last_modified_user": "admin",
  "_last_modified_time": 1603876242547,
  "_protection": "NOT_PROTECTED",
  "_revision": 0
}
16:33:12 : remove-temp-segment-groups.ps1: line 316, remove-temp-segment-groups.ps1: VERBOSE: segmentWrapperGroup received via API.
{
  "expression": [
    {
      "paths": [
        "/infra/segments/v12343_nsx_prod_net_internal"
      ],
      "resource_type": "PathExpression",
      "id": "d930cf86-e508-4677-89f8-ec43b50471ba",
      "path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal/path-expressions/d930cf86-e508-4677-89f8-ec43b50471ba",
      "relative_path": "d930cf86-e508-4677-89f8-ec43b50471ba",
      "parent_path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal",
      "marked_for_delete": false,
      "overridden": false,
      "_protection": "NOT_PROTECTED"
    },
    {
      "conjunction_operator": "OR",
      "resource_type": "ConjunctionOperator",
      "id": "d51e9d7b-df1d-4b0d-9aa6-097705746f0e",
      "path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal/conjunction-expressions/d51e9d7b-df1d-4b0d-9aa6-097705746f0e",
      "relative_path": "d51e9d7b-df1d-4b0d-9aa6-097705746f0e",
      "parent_path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal",
      "marked_for_delete": false,
      "overridden": false,
      "_protection": "NOT_PROTECTED"
    },
    {
      "ip_addresses": [
        "10.10.10.0/24",
        "1.1.1.1/32",
        "10.10.11.0/24"
      ],
      "resource_type": "IPAddressExpression",
      "id": "9aeaffa9-e376-4e47-8055-95410fac976d",
      "path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal/ip-address-expressions/9aeaffa9-e376-4e47-8055-95410fac976d",
      "relative_path": "9aeaffa9-e376-4e47-8055-95410fac976d",
      "parent_path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal",
      "marked_for_delete": false,
      "overridden": false,
      "_protection": "NOT_PROTECTED"
    }
  ],
  "extended_expression": [],
  "reference": false,
  "resource_type": "Group",
  "id": "v12343_nsx_prod_net_internal",
  "display_name": "v12343_nsx_prod_net_internal",
  "tags": [
    {
      "scope": "migration/portprofile",
      "tag": "ESX01-HTC_PREP_EXT"
    },
    {
      "scope": "migration/tempIp",
      "tag": "10.10.11.0/24"
    },
    {
      "scope": "migration/tempIp",
      "tag": "5.5.5.0/22"
    }
  ],
  "path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal",
  "relative_path": "v12343_nsx_prod_net_internal",
  "parent_path": "/infra/domains/default",
  "unique_id": "856145d4-df2b-4c05-8620-1c393fc08bc2",
  "marked_for_delete": false,
  "overridden": false,
  "_system_owned": false,
  "_create_user": "admin",
  "_create_time": 1603876278227,
  "_last_modified_user": "admin",
  "_last_modified_time": 1605072728935,
  "_protection": "NOT_PROTECTED",
  "_revision": 19
}
16:33:12 : remove-temp-segment-groups.ps1: line 378, remove-temp-segment-groups.ps1: VERBOSE: Ignoring PathExpression
16:33:12 : remove-temp-segment-groups.ps1: line 378, remove-temp-segment-groups.ps1: VERBOSE: Ignoring PathExpression
16:33:12 : remove-temp-segment-groups.ps1: line 378, remove-temp-segment-groups.ps1: VERBOSE: Ignoring ConjunctionOperator
16:33:12 : remove-temp-segment-groups.ps1: line 378, remove-temp-segment-groups.ps1: VERBOSE: Ignoring ConjunctionOperator
16:33:12 : remove-temp-segment-groups.ps1: line 349, remove-temp-segment-groups.ps1: VERBOSE: Found address '10.10.11.0/24' in IpExpression
16:33:12 : remove-temp-segment-groups.ps1: line 367, remove-temp-segment-groups.ps1: VERBOSE: Found 3 address entries. Only going to remove address: '10.10.11.0/24'
16:33:12 : remove-temp-segment-groups.ps1: line 375, remove-temp-segment-groups.ps1: VERBOSE: IPAddressExpression does not tag address '5.5.5.0/22'.
16:33:12 : remove-temp-segment-groups.ps1: line 387, remove-temp-segment-groups.ps1: VERBOSE: Group is required to be updated via PATCH
16:33:12 : remove-temp-segment-groups.ps1: line 394, remove-temp-segment-groups.ps1: VERBOSE: Removing tag pair with scope 'migration/tempIp' at index 1
16:33:12 : remove-temp-segment-groups.ps1: line 402, remove-temp-segment-groups.ps1: VERBOSE: Patching updated configuration for group: v12343_nsx_prod_net_internal
{
  "expression": [
    {
      "paths": [
        "/infra/segments/v12343_nsx_prod_net_internal"
      ],
      "resource_type": "PathExpression",
      "id": "d930cf86-e508-4677-89f8-ec43b50471ba",
      "path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal/path-expressions/d930cf86-e508-4677-89f8-ec43b50471ba",
      "relative_path": "d930cf86-e508-4677-89f8-ec43b50471ba",
      "parent_path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal",
      "marked_for_delete": false,
      "overridden": false,
      "_protection": "NOT_PROTECTED"
    },
    {
      "conjunction_operator": "OR",
      "resource_type": "ConjunctionOperator",
      "id": "d51e9d7b-df1d-4b0d-9aa6-097705746f0e",
      "path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal/conjunction-expressions/d51e9d7b-df1d-4b0d-9aa6-097705746f0e",
      "relative_path": "d51e9d7b-df1d-4b0d-9aa6-097705746f0e",
      "parent_path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal",
      "marked_for_delete": false,
      "overridden": false,
      "_protection": "NOT_PROTECTED"
    },
    {
      "ip_addresses": [
        "10.10.10.0/24",
        "1.1.1.1/32"
      ],
      "resource_type": "IPAddressExpression",
      "id": "9aeaffa9-e376-4e47-8055-95410fac976d",
      "path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal/ip-address-expressions/9aeaffa9-e376-4e47-8055-95410fac976d",
      "relative_path": "9aeaffa9-e376-4e47-8055-95410fac976d",
      "parent_path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal",
      "marked_for_delete": false,
      "overridden": false,
      "_protection": "NOT_PROTECTED"
    }
  ],
  "extended_expression": [],
  "reference": false,
  "resource_type": "Group",
  "id": "v12343_nsx_prod_net_internal",
  "display_name": "v12343_nsx_prod_net_internal",
  "tags": [
    {
      "scope": "migration/portprofile",
      "tag": "ESX01-HTC_PREP_EXT"
    },
    {
      "scope": "migration/tempIp",
      "tag": "5.5.5.0/22"
    }
  ],
  "path": "/infra/domains/default/groups/v12343_nsx_prod_net_internal",
  "relative_path": "v12343_nsx_prod_net_internal",
  "parent_path": "/infra/domains/default",
  "unique_id": "856145d4-df2b-4c05-8620-1c393fc08bc2",
  "marked_for_delete": false,
  "overridden": false,
  "_system_owned": false,
  "_create_user": "admin",
  "_create_time": 1603876278227,
  "_last_modified_user": "admin",
  "_last_modified_time": 1605072728935,
  "_protection": "NOT_PROTECTED",
  "_revision": 19
}
16:33:14 : remove-temp-segment-groups.ps1: line 422, remove-temp-segment-groups.ps1: INFO: Script duration = 00:00:05.3028640
```
