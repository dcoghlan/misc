# count-dataplane-rules

A script created to calculate the count of firewall rules on the dataplane of a given Virtual Machine using PowerNSX. The script uses the Central-CLI API which requires a CLI User account (only requires read-only permissions).

## Modes

The script operates in 3 main modes. Each mode is required to have a VM name supplied.

### All Rules

```
PS C:\Users\Administrator> .\count-dataplane-rules.ps1 -Username admin -Password VMware1!VMware1! -Server 192.168.110.190  -VmName Dummy-011

--------------------------------------------------------------------------------

  Script Mode: AllRules
  Logging File: 2020-06-09-082815-log.txt
  Rule Details: 2020-06-09-082815-details.csv

--------------------------------------------------------------------------------

 --> Found existing PowerNSX connection: (192.168.110.190)
 --> Disconnecting from NSX Manager: (192.168.110.190)
 --> Establishing new PowerNSX connection to 192.168.110.190
Using existing PowerCLI connection to 192.168.110.11
 --> Retrieving rule ids from all sections... OK
 --> Retrieving DFW Clusters... OK

 --> Processing DFW Cluster: S1 Compute Cluster
   --> Retrieving DFW Hosts...OK
     --> Retrieving filters: esxcomp-01a.corp.local... OK
     --> Retrieving filters: esxcomp-02a.corp.local... OK

Execution completed in 0:0:8
```

### Section

```
PS C:\Users\Administrator> .\count-dataplane-rules.ps1 -Username admin -Password VMware1!VMware1! -Server 192.168.110.190  -VmName Dummy-011 -SectionName Moe

--------------------------------------------------------------------------------

  Script Mode: Section
  Logging File: 2020-06-09-082635-log.txt
  Rule Details: 2020-06-09-082635-details.csv

--------------------------------------------------------------------------------

 --> Found existing PowerNSX connection: (192.168.110.190)
 --> Disconnecting from NSX Manager: (192.168.110.190)
 --> Establishing new PowerNSX connection to 192.168.110.190
Using existing PowerCLI connection to 192.168.110.11
 --> Retrieving rule ids from section: Moe... OK
 --> Retrieving DFW Clusters... OK

 --> Processing DFW Cluster: S1 Compute Cluster
   --> Retrieving DFW Hosts...OK
     --> Retrieving filters: esxcomp-01a.corp.local... OK
     --> Retrieving filters: esxcomp-02a.corp.local... OK

Execution completed in 0:0:8
```

### Rule ID

```
PS C:\Users\Administrator> .\count-dataplane-rules.ps1 -Username admin -Password VMware1!VMware1! -Server 192.168.110.190  -VmName Dummy-011 -ruleid 1005

--------------------------------------------------------------------------------

  Script Mode: RuleId
  Logging File: 2020-06-09-082441-log.txt
  Rule Details: 2020-06-09-082441-details.csv

--------------------------------------------------------------------------------

 --> Found existing PowerNSX connection: (192.168.110.190)
 --> Disconnecting from NSX Manager: (192.168.110.190)
 --> Establishing new PowerNSX connection to 192.168.110.190
Using existing PowerCLI connection to 192.168.110.11
 --> Retrieving DFW Clusters... OK

 --> Processing DFW Cluster: S1 Compute Cluster
   --> Retrieving DFW Hosts...OK
     --> Retrieving filters: esxcomp-01a.corp.local... OK
     --> Retrieving filters: esxcomp-02a.corp.local... OK

Execution completed in 0:0:7
```

## Output Files

All modes of the script produce the same outputs.
 - Detailed log file
 - CSV File (Example below)

 ```
RuleId,RuleCount
1008, 16
1007, 26
1006, 3
1005, 1
1003, 2
1002, 2
1001, 1
1004, 1
Total, 52
 ```