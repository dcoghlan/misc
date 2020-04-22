# My Miscellaneous Repo

A dumping ground for some miscellaneous scripts written for various purposes.

## Scripts

`/NSX-V/ConvertVMstoUniversalIpSets.ps1` - A small script using PowerNSX to find all the VM objects and create a universal IP Set which represents the IPv4 VM object. This is a 1-Time use script only. Running it multiple times will created multiple IP Sets objects for the same VM, so please test this first in a non-production environment.

`/NSX-V/Host-vNic-Collection/host-vnic-collector.ps1` - A quick script to use the Central CLI API to gather the number of DFW filters on all the DFW enabled hosts. More details can be found in the file `/NSX-v/Host-vNic-Collection/README.MD`

`/NSX-V/Capture-Nsx-Tag-Assignment/capture-nsx-tag-assignment.ps1` - A quick script to capture the NSX Security Tag assignments. Useful for backing up or migration activities.

`NSX-V/Capture-VM-IDs/capture-vm-ids.ps1` - A quick script to capture the UUID and InstanceUUID of every VM. Useful when working with NSX-T as virtual machines in the inventory are referenced by either the UUID or InstanceID.
