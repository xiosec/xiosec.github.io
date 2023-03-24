---
title: "Masquerading Processes via PEB"
date: 2023-03-24T17:33:51+03:30
tags: ['security','RedTeam', 'internals', 'Defense-Evasion']
categories: ['security', 'RedTeam']
images: ['/assets/post/Masquerade-PEB/process.png']
description: 'In this post, we explain how to show a process with the information from another process by changing the Block Process Environment (abbreviated as PEB)'
---

In this post, we explain how to show a process with the information from another process by changing the Block Process Environment (abbreviated as PEB)

## Overview

The information of a process, such as `arguments`, `image location`, `loaded modules`, etc., is stored in a structure called the `process environment block (_PEB)` in memory, which can be accessed through the `userland` and whose values can be edited.

> Tools like `ProcExplorer` display some process information by looking at the `_PEB`.

## Scenario

The scenario is that `mimikatz.exe` is running. We need to change its `path` and `command line` value using `WinDBG`.

![Scenario](/assets/post/Masquerade-PEB/scenario.png)

## Execution

Let's first take a look at the `_PEB` structure for the mimikatz.exe process:

```shell
dt _peb @$peb
```

![PEB](/assets/post/Masquerade-PEB/peb.png)

At offset `0x020` of the PEB, there is another structure `_RTL_USER_PROCESS_PARAMETERS`, which contains information about the mimikatz.exe process. Let's check it out:

```shell
dt _RTL_USER_PROCESS_PARAMETERS 0x00000000``00be1d00
```

![Parameters](/assets/post/Masquerade-PEB/parameters.png)

Offset `0x060` `_RTL_USER_PROCESS_PARAMETERS` contains an `ImagePathName` member that points to a `_UNICODE_STRING` structure that contains a Buffer field that effectively represents the full name/path to our binary mimikatz.exe.

```shell
dt _UNICODE_STRING 0x00000000``00be1d00+0x060

# output

ntdll!_UNICODE_STRING
 "E:\tools\mimikatz_trunk\x64\mimikatz.exe"
   +0x000 Length           : 0x50
   +0x002 MaximumLength    : 0x52
   +0x008 Buffer           : 0x00000000``00be2348  "E:\tools\mimikatz_trunk\x64\mimikatz.exe"
```

We know that ‍`0x00000000 00be2348‍` contains the binary path, let's write a new string at that memory address. let's move mimikatz.exe with a path to the notepad.exe binary located in `C:\Windows\System32\notepad.exe`:

```shell
eu 0x00000000``00be2348 "C:\\Windows\\System32\\notepad.exe"
```

We change the `commandline` in the same way:

```shell
eu 0x00000000``00be239a "C:\\Windows\\System32\\notepad.exe"
```

Now let's see ‍`ProcessParameters` again:

```shell
dt _RTL_USER_PROCESS_PARAMETERS 0x00000000``00be1d00
```
![New Parameters](/assets/post/Masquerade-PEB/newparameters.png)

Let's look at the mimikatz.exe process again with Process Explorer:

![process](/assets/post/Masquerade-PEB/process.png)

## References

* [RTL_USER_PROCESS_PARAMETERS structure (winternl.h)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters)
* [PEB structure (winternl.h)](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
* [Masquerading Processes in Userland via _PEB](https://www.ired.team/offensive-security/defense-evasion/masquerading-processes-in-userland-through-_peb)
