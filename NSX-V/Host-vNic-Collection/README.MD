A quick script to use the Central CLI API to gather the number of DFW filters on all the DFW enabled hosts.

## Console Output

```
PS C:\Users\Administrator> .\host-vnic-collector.ps1 -Server 192.168.101.201 -Username admin -Password VMware1! -Environment SG1

Logging File: SG1-2020-04-01-220429-log.txt
vNic Details: SG1-2020-04-01-220429-details.csv

Found existing PowerNSX connection: (192.168.101.201)
Disconnecting from NSX Manager: (192.168.101.201)
Establishing new PowerNSX connection to 192.168.101.201
Using existing PowerCLI connection to 192.168.101.11


Version             : 6.4.6
BuildNumber         : 14819921
Credential          : System.Management.Automation.PSCredential
Server              : 192.168.101.201
Port                : 443
Protocol            : https
UriPrefix           :
ValidateCertificate : False
VIConnection        : vc-01a.corp.local
DebugLogging        : False
DebugLogfile        : C:\Users\ADMINI~1\AppData\Local\Temp\2\PowerNSXLog-admin@192.168.101.201-2020_04_01_22_41_29.log

 --> Retrieving DFW Clusters... OK

 --> Processing DFW Cluster: Mgmt01_a
   --> Retrieving DFW Hosts...OK
     --> Retrieving filters: mgt-esxi1a.corp.local... OK
     --> Retrieving filters: mgt-esxi2a.corp.local... OK
     --> Retrieving filters: mgt-esxi3a.corp.local... OK
     --> Retrieving filters: mgt-esxi4a.corp.local... OK

 --> Processing DFW Cluster: Compute01_a
   --> Retrieving DFW Hosts...OK
     --> Retrieving filters: compute01-esxi1a.corp.local... OK
     --> Retrieving filters: compute01-esxi2a.corp.local... OK
     --> Retrieving filters: compute01-esxi3a.corp.local... OK

Execution completed in 0:0:14
```

## CSV Output File

```
cluster_id, cluster_name, host_id, host_name, sfw.2_count, Date, Time
domain-c46, Mgmt01_a, host-57, mgt-esxi1a.corp.local, 0, 2020-04-01, 22:04:35
domain-c46, Mgmt01_a, host-59, mgt-esxi2a.corp.local, 0, 2020-04-01, 22:04:36
domain-c46, Mgmt01_a, host-60, mgt-esxi3a.corp.local, 0, 2020-04-01, 22:04:38
domain-c46, Mgmt01_a, host-61, mgt-esxi4a.corp.local, 0, 2020-04-01, 22:04:39
domain-c63, Compute01_a, host-67, compute01-esxi1a.corp.local, 5, 2020-04-01, 22:04:41
domain-c63, Compute01_a, host-68, compute01-esxi2a.corp.local, 0, 2020-04-01, 22:04:42
domain-c63, Compute01_a, host-69, compute01-esxi3a.corp.local, 0, 2020-04-01, 22:04:43
```

## Log Output File

```
22:41:29 : host-vnic-collector.ps1: line 100, host-vnic-collector.ps1: DEBUG: PowerNSX Connection Details
22:41:29 : host-vnic-collector.ps1: line 101, host-vnic-collector.ps1: DEBUG:

Version             : 6.4.6
BuildNumber         : 14819921
Credential          : System.Management.Automation.PSCredential
Server              : 192.168.101.201
Port                : 443
Protocol            : https
UriPrefix           :
ValidateCertificate : False
VIConnection        : vc-01a.corp.local
DebugLogging        : False
DebugLogfile        : C:\Users\ADMINI~1\AppData\Local\Temp\2\PowerNSXLog-admin@192.168.101.201-2020_04_01_22_41_29.log




22:41:29 : host-vnic-collector.ps1: line 107, host-vnic-collector.ps1: DEBUG: Executing: show dfw cluster all
22:41:32 : host-vnic-collector.ps1: line 109, host-vnic-collector.ps1: DEBUG: Response:
Cluster Name Cluster Id Datacenter Name Firewall Fabric Status Firewall Status
------------ ---------- --------------- ---------------------- ---------------
Mgmt01_a     domain-c46 CloudLab_SiteA  GREEN                  Enabled
Compute01_a  domain-c63 CloudLab_SiteA  GREEN                  Enabled



22:41:32 : host-vnic-collector.ps1: line 127, host-vnic-collector.ps1: DEBUG: Executing: show dfw cluster domain-c46
22:41:34 : host-vnic-collector.ps1: line 129, host-vnic-collector.ps1: DEBUG: Response:
Host Id Datacenter     Firewall Fabric Status Cluster  Installation Status Host Name
------- ----------     ---------------------- -------  ------------------- ---------
host-57 CloudLab_SiteA GREEN                  Mgmt01_a Enabled             mgt-esxi1a.corp.local
host-59 CloudLab_SiteA GREEN                  Mgmt01_a Enabled             mgt-esxi2a.corp.local
host-60 CloudLab_SiteA GREEN                  Mgmt01_a Enabled             mgt-esxi3a.corp.local
host-61 CloudLab_SiteA GREEN                  Mgmt01_a Enabled             mgt-esxi4a.corp.local



22:41:34 : host-vnic-collector.ps1: line 145, host-vnic-collector.ps1: DEBUG: Executing: show dfw host host-57 summarize-dvfilter
22:41:35 : host-vnic-collector.ps1: line 147, host-vnic-collector.ps1: DEBUG: Response: Fastpaths:
agent: dvfilter-faulter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter
agent: ESXi-Firewall, refCount: 3, rev: 0x1010000, apiRev: 0x1010000, module: esxfw
agent: dvfilter-generic-vmware, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter-generic-fastpath
agent: dvfilter-generic-vmware-swsec, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: nsx-dvfilter-switch-security
agent: bridgelearningfilter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vdrb
agent: vmware-sfw, refCount: 4, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vsip

Slowpaths:
slowPath: 1, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 2, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 3, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso

Filters:
world 0 <no world>
 port 33554436 vmk0
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
 port 50331652 vmk1
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid


22:41:35 : host-vnic-collector.ps1: line 145, host-vnic-collector.ps1: DEBUG: Executing: show dfw host host-59 summarize-dvfilter
22:41:36 : host-vnic-collector.ps1: line 147, host-vnic-collector.ps1: DEBUG: Response: Fastpaths:
agent: dvfilter-faulter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter
agent: ESXi-Firewall, refCount: 3, rev: 0x1010000, apiRev: 0x1010000, module: esxfw
agent: dvfilter-generic-vmware, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter-generic-fastpath
agent: dvfilter-generic-vmware-swsec, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: nsx-dvfilter-switch-security
agent: bridgelearningfilter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vdrb
agent: vmware-sfw, refCount: 4, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vsip

Slowpaths:
slowPath: 1, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 2, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 3, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso

Filters:
world 0 <no world>
 port 33554436 vmk0
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
 port 50331652 vmk1
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid


22:41:36 : host-vnic-collector.ps1: line 145, host-vnic-collector.ps1: DEBUG: Executing: show dfw host host-60 summarize-dvfilter
22:41:38 : host-vnic-collector.ps1: line 147, host-vnic-collector.ps1: DEBUG: Response: Fastpaths:
agent: dvfilter-faulter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter
agent: ESXi-Firewall, refCount: 3, rev: 0x1010000, apiRev: 0x1010000, module: esxfw
agent: dvfilter-generic-vmware, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter-generic-fastpath
agent: dvfilter-generic-vmware-swsec, refCount: 4, rev: 0x1010000, apiRev: 0x1010000, module: nsx-dvfilter-switch-security
agent: bridgelearningfilter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vdrb
agent: vmware-sfw, refCount: 4, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vsip

Slowpaths:
slowPath: 1, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 2, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 3, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso

Filters:
world 0 <no world>
 port 33554436 vmk0
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
 port 50331652 vmk1
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
world 68915 vmm0:Dlr01-0 vcUuid:'50 01 37 01 d8 2e 05 07-31 6a 58 82 52 54 bb da'
 port 50331655 Dlr01-0.eth0
  vNic slot 1
  name: nic-68915-eth0-dvfilter-generic-vmware-swsec.1
 agentName: dvfilter-generic-vmware-swsec
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failClosed
   slowPathID: none
   filter source: Alternate Opaque Channel
 port 50331654 Dlr01-0.eth2
  vNic slot 1
  name: nic-68915-eth2-dvfilter-generic-vmware-swsec.1
 agentName: dvfilter-generic-vmware-swsec
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failClosed
   slowPathID: none
   filter source: Alternate Opaque Channel
world 68924 vmm0:Edge01-0 vcUuid:'50 01 e6 88 8e 4f 43 63-f3 90 b2 fa ea 1e 15 59'
 port 50331656 Edge01-0.eth1
  vNic slot 1
  name: nic-68924-eth1-dvfilter-generic-vmware-swsec.1
 agentName: dvfilter-generic-vmware-swsec
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failClosed
   slowPathID: none
   filter source: Alternate Opaque Channel


22:41:38 : host-vnic-collector.ps1: line 145, host-vnic-collector.ps1: DEBUG: Executing: show dfw host host-61 summarize-dvfilter
22:41:39 : host-vnic-collector.ps1: line 147, host-vnic-collector.ps1: DEBUG: Response: Fastpaths:
agent: dvfilter-faulter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter
agent: ESXi-Firewall, refCount: 3, rev: 0x1010000, apiRev: 0x1010000, module: esxfw
agent: dvfilter-generic-vmware, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter-generic-fastpath
agent: dvfilter-generic-vmware-swsec, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: nsx-dvfilter-switch-security
agent: bridgelearningfilter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vdrb
agent: vmware-sfw, refCount: 4, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vsip

Slowpaths:
slowPath: 1, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 2, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 3, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso

Filters:
world 0 <no world>
 port 33554436 vmk0
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
 port 50331652 vmk1
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid


22:41:39 : host-vnic-collector.ps1: line 127, host-vnic-collector.ps1: DEBUG: Executing: show dfw cluster domain-c63
22:41:40 : host-vnic-collector.ps1: line 129, host-vnic-collector.ps1: DEBUG: Response:
Host Id Datacenter     Firewall Fabric Status Cluster     Installation Status Host Name
------- ----------     ---------------------- -------     ------------------- ---------
host-67 CloudLab_SiteA GREEN                  Compute01_a Enabled             compute01-esxi1a.corp.local
host-68 CloudLab_SiteA GREEN                  Compute01_a Enabled             compute01-esxi2a.corp.local
host-69 CloudLab_SiteA GREEN                  Compute01_a Enabled             compute01-esxi3a.corp.local



22:41:40 : host-vnic-collector.ps1: line 145, host-vnic-collector.ps1: DEBUG: Executing: show dfw host host-67 summarize-dvfilter
22:41:41 : host-vnic-collector.ps1: line 147, host-vnic-collector.ps1: DEBUG: Response: Fastpaths:
agent: dvfilter-faulter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter
agent: ESXi-Firewall, refCount: 3, rev: 0x1010000, apiRev: 0x1010000, module: esxfw
agent: dvfilter-generic-vmware, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter-generic-fastpath
agent: dvfilter-generic-vmware-swsec, refCount: 6, rev: 0x1010000, apiRev: 0x1010000, module: nsx-dvfilter-switch-security
agent: bridgelearningfilter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vdrb
agent: vmware-sfw, refCount: 9, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vsip

Slowpaths:
slowPath: 1, agent vmware-sfw, refCount: 3, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 2, agent vmware-sfw, refCount: 3, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 3, agent vmware-sfw, refCount: 2, rev: 0x4, apiRev: 0x4, capabilities: csum,tso

Filters:
world 0 <no world>
 port 33554436 vmk0
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
 port 50331652 vmk1
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
world 1033246 vmm0:Web02 vcUuid:'50 01 2f 3f 98 da b0 da-6c 2a 30 15 d8 41 67 6c'
 port 50331769 Web02.eth0
  vNic slot 2
  name: nic-1033246-eth0-vmware-sfw.2
 agentName: vmware-sfw
   state: IOChain Attached
   vmState: Attached
   failurePolicy: failClosed
   slowPathID: 1
   filter source: Dynamic Filter Creation
  vNic slot 1
  name: nic-1033246-eth0-dvfilter-generic-vmware-swsec.1
 agentName: dvfilter-generic-vmware-swsec
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failClosed
   slowPathID: none
   filter source: Alternate Opaque Channel
world 1043320 vmm0:App01 vcUuid:'50 01 d7 0e ad d1 be 8e-ad 9d 06 8e 48 83 cc 4f'
 port 50331776 App01.eth0
  vNic slot 2
  name: nic-1043320-eth0-vmware-sfw.2
 agentName: vmware-sfw
   state: IOChain Attached
   vmState: Attached
   failurePolicy: failClosed
   slowPathID: 1
   filter source: Dynamic Filter Creation
  vNic slot 1
  name: nic-1043320-eth0-dvfilter-generic-vmware-swsec.1
 agentName: dvfilter-generic-vmware-swsec
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failClosed
   slowPathID: none
   filter source: Alternate Opaque Channel
world 1066354 vmm0:Web01 vcUuid:'50 01 7d f1 e7 8c 30 f8-2e ae a5 06 cc b5 5b df'
 port 50331779 Web01.eth0
  vNic slot 2
  name: nic-1066354-eth0-vmware-sfw.2
 agentName: vmware-sfw
   state: IOChain Attached
   vmState: Attached
   failurePolicy: failClosed
   slowPathID: 2
   filter source: Dynamic Filter Creation
  vNic slot 1
  name: nic-1066354-eth0-dvfilter-generic-vmware-swsec.1
 agentName: dvfilter-generic-vmware-swsec
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failClosed
   slowPathID: none
   filter source: Alternate Opaque Channel
world 1066900 vmm0:DB01 vcUuid:'50 01 05 0b ca c9 a2 a4-fc 80 15 4c 96 f7 d8 30'
 port 50331780 DB01.eth0
  vNic slot 2
  name: nic-1066900-eth0-vmware-sfw.2
 agentName: vmware-sfw
   state: IOChain Attached
   vmState: Attached
   failurePolicy: failClosed
   slowPathID: 2
   filter source: Dynamic Filter Creation
  vNic slot 1
  name: nic-1066900-eth0-dvfilter-generic-vmware-swsec.1
 agentName: dvfilter-generic-vmware-swsec
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failClosed
   slowPathID: none
   filter source: Alternate Opaque Channel
world 1218777 vmm0:App02 vcUuid:'50 01 8e 21 ba 3c bc 59-1b b6 8d f8 b0 2e 52 16'
 port 50331782 App02.eth0
  vNic slot 2
  name: nic-1218777-eth0-vmware-sfw.2
 agentName: vmware-sfw
   state: IOChain Attached
   vmState: Attached
   failurePolicy: failClosed
   slowPathID: 3
   filter source: Dynamic Filter Creation
  vNic slot 1
  name: nic-1218777-eth0-dvfilter-generic-vmware-swsec.1
 agentName: dvfilter-generic-vmware-swsec
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failClosed
   slowPathID: none
   filter source: Alternate Opaque Channel


22:41:41 : host-vnic-collector.ps1: line 145, host-vnic-collector.ps1: DEBUG: Executing: show dfw host host-68 summarize-dvfilter
22:41:42 : host-vnic-collector.ps1: line 147, host-vnic-collector.ps1: DEBUG: Response: Fastpaths:
agent: dvfilter-faulter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter
agent: ESXi-Firewall, refCount: 3, rev: 0x1010000, apiRev: 0x1010000, module: esxfw
agent: dvfilter-generic-vmware, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter-generic-fastpath
agent: dvfilter-generic-vmware-swsec, refCount: 2, rev: 0x1010000, apiRev: 0x1010000, module: nsx-dvfilter-switch-security
agent: bridgelearningfilter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vdrb
agent: vmware-sfw, refCount: 4, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vsip

Slowpaths:
slowPath: 1, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 2, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 3, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso

Filters:
world 0 <no world>
 port 33554436 vmk0
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
 port 50331652 vmk1
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
world 1030819 vmm0:BITW-edge-2 vcUuid:'50 01 b3 9b 51 da 51 81-88 23 e8 0b ad ac b3 f9'
 port 50331770 BITW-edge-2.eth1
  vNic slot 1
  name: nic-1030819-eth1-dvfilter-generic-vmware-swsec.1
 agentName: dvfilter-generic-vmware-swsec
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failClosed
   slowPathID: none
   filter source: Alternate Opaque Channel


22:41:42 : host-vnic-collector.ps1: line 145, host-vnic-collector.ps1: DEBUG: Executing: show dfw host host-69 summarize-dvfilter
22:41:43 : host-vnic-collector.ps1: line 147, host-vnic-collector.ps1: DEBUG: Response: Fastpaths:
agent: dvfilter-faulter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter
agent: ESXi-Firewall, refCount: 3, rev: 0x1010000, apiRev: 0x1010000, module: esxfw
agent: dvfilter-generic-vmware, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfilter-generic-fastpath
agent: dvfg-igmp, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: dvfg-igmp
agent: dvfilter-generic-vmware-swsec, refCount: 2, rev: 0x1010000, apiRev: 0x1010000, module: nsx-dvfilter-switch-security
agent: bridgelearningfilter, refCount: 1, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vdrb
agent: vmware-sfw, refCount: 4, rev: 0x1010000, apiRev: 0x1010000, module: nsx-vsip

Slowpaths:
slowPath: 1, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 2, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso
slowPath: 3, agent vmware-sfw, refCount: 1, rev: 0x4, apiRev: 0x4, capabilities: csum,tso

Filters:
world 0 <no world>
 port 33554436 vmk0
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
 port 50331652 vmk1
  vNic slot 0
  name: nic-0-eth4294967295-ESXi-Firewall.0
 agentName: ESXi-Firewall
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failOpen
   slowPathID: none
   filter source: Invalid
world 926156 vmm0:BITW-edge-1 vcUuid:'50 01 99 22 87 f0 2b 19-8e d0 35 3f 13 ce 86 a4'
 port 50331658 BITW-edge-1.eth1
  vNic slot 1
  name: nic-926156-eth1-dvfilter-generic-vmware-swsec.1
 agentName: dvfilter-generic-vmware-swsec
   state: IOChain Attached
   vmState: Detached
   failurePolicy: failClosed
   slowPathID: none
   filter source: Alternate Opaque Channel



```
