# misc
A dumping ground for some miscellaneous scripts written for various purposes.

# /NSX-V/
```ConvertVMstoUniversalIpSets.ps1```
A small script using PowerNSX to find all the VM objects and create a universal IP Set which represents the IPv4 VM object. This is a 1-Time use script only. Running it multiple times will created multiple IP Sets objects for the same VM, so please test this first in a non-production environment.
