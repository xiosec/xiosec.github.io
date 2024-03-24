---
title: "Direct Kernel Object Manipulation (DKOM)"
date: 2023-05-17T15:17:34+03:30
tags: ['security','RedTeam', 'internals', 'kernel']
categories: ['security', 'internals']
images: ['/assets/post/Dkom/dt_list_entry.png']
description: 'In this post, we talk about manipulating the _EPROCESS structure in the kernel and how to hide processes.'
---

In this post, we talk about manipulating the _EPROCESS structure in the kernel and how to hide processes.

## Overview

In most cases, rootkits can hide a process by exploiting various kernel structures such as `_EPROCESS`.

EPROCESS is a kernel memory structure that describes system-related processes, in fact, every process that runs on the system has a unique _EPROCESS object that is stored somewhere in the kernel.
This object contains various things like process ID or structures like `_PEB (Process Environment Block)`.

Using Windbg, we can see the `_EPROCESS` structure

```bash
0: kd> dt _eprocess
ntdll!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
#  +0x440 UniqueProcessId  : Ptr64 Void
#  +0x448 ActiveProcessLinks : _LIST_ENTRY
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
   +0x460 Flags2           : Uint4B
   +0x460 JobNotReallyActive : Pos 0, 1 Bit
   +0x460 AccountingFolded : Pos 1, 1 Bit
   +0x460 NewProcessReported : Pos 2, 1 Bit
   +0x460 ExitProcessReported : Pos 3, 1 Bit
   +0x460 ReportCommitChanges : Pos 4, 1 Bit
   +0x460 LastReportMemory : Pos 5, 1 Bit
   +0x460 ForceWakeCharge  : Pos 6, 1 Bit
   +0x460 CrossSessionCreate : Pos 7, 1 Bit
   +0x460 NeedsHandleRundown : Pos 8, 1 Bit
   +0x460 RefTraceEnabled  : Pos 9, 1 Bit
   +0x460 PicoCreated      : Pos 10, 1 Bit
   +0x460 EmptyJobEvaluated : Pos 11, 1 Bit
   +0x460 DefaultPagePriority : Pos 12, 3 Bits
   +0x460 PrimaryTokenFrozen : Pos 15, 1 Bit
   +0x460 ProcessVerifierTarget : Pos 16, 1 Bit
   +0x460 RestrictSetThreadContext : Pos 17, 1 Bit
   +0x460 AffinityPermanent : Pos 18, 1 Bit
   +0x460 AffinityUpdateEnable : Pos 19, 1 Bit
   +0x460 PropagateNode    : Pos 20, 1 Bit
   ...
```

One of the important fields of this structure is `ActiveProcessLinks`, which is a pointer to another structure called `LIST_ENTRY`.

```bash
0: kd> dt _LIST_ENTRY
ntdll!_LIST_ENTRY
   +0x000 Flink            : Ptr64 _LIST_ENTRY
   +0x008 Blink            : Ptr64 _LIST_ENTRY
```

LIST_ENTRY is actually a double link list that contains two fields `FLINK (forward link)` and `BLINK (backward link)` that refer to the elements before and after it.

![](/assets/post/Dkom/list_entry.png)

All processes have their own core objects in the form of the EPROCESS core structure. All those EPROCESS objects are stored in a doubly linked list.

> In fact, when we request the list of running processes from the operating system, Windows uses `LIST_ENTRY` structures through the doubly linked list of `EPROCESS` nodes and retrieves the information of each process.

According to the above content, rootkits can hide a process from the user's view by manipulating the connections of the nodes

If we separate EPROCESS 2 from the previous node (EPROCESS 1) and the next node (EPROCESS 3) in the `doubly linked list`, the process in question becomes practically invisible to all userland APIs that retrieve the running processes of the system.

![](/assets/post/Dkom/change.jpeg)

## Example

For this lab, we run a sample process like a calculator and try to hide it

![](/assets/post/Dkom/process.png)

Using `Windbg` and in kernel mode, we can get more information about the process we want

```bash
# 17c8 = hex(6088)

0: kd> !process 17c8 0
Searching for Process with Cid == 17c8
PROCESS ffff958f8f611080
    SessionId: 1  Cid: 17c8    Peb: 5c5046000  ParentCid: 0310
    DirBase: 8d8cf000  ObjectTable: ffff80017c0a1a40  HandleCount: 478.
    Image: Calculator.exe

```

According to the output of the above command, the `EPROCESS` structure is located at `ffff958f8f611080`

```bash
0: kd> dt _eprocess ffff958f8f611080
```
![](/assets/post/Dkom/dt_eprocess.png)

As you can see, ActiveProcessLinks is a doubly linked list filled with two pointers `(Flink and Blink)`.

We can read those values with `dt _list_entry ffff958f8f611080+448` or just `dq ffff958f8f611080+448 L2`:

```bash
0: kd> dq ffff958f8f611080+448 L2
ffff958f`8f6114c8  ffff958f`8b9c2708 ffff958f`8e4b3748
```

![](/assets/post/Dkom/dt_list_entry.png)

Now we can find the previous and next `EPROCESS` nodes that `Calculator.exe` points to.

* `FLINK` points to **0xffff958f\`8b9c2708**

* `BLINK` points to **0xffff958f\`8e4b3748**

We can check the process image name referenced by calculator FLINK at **0xffff958f\`8b9c2708**

```bash
# EPROCESS - ActiveProcessLinks (0x448) + ImageFileName (0x5a8)

0: kd> da 0xffff958f`8b9c2708 - 448 + 5a8
ffff958f`8b9c2868  "svchost.exe"
```

We do the same for BLINK:

```bash
0: kd> da 0xffff958f`8e4b3748 - 448 + 5a8
ffff958f`8e4b38a8  "ApplicationFra" # ApplicationFrameHost
```

So far, we noticed that our process is located between two processes, svchost.exe and `ApplicationFrameHost.exe`.
Using the following formula, we can get the PIDs of each process

```bash
(FLINK or BLINK) - ActiveProcessLinks (0x448) + UniqueProcessId (440)
```

![](/assets/post/Dkom/pids.png)

### Change links

The table below is the `FLINK` and `BLINK` pointers of our target processes

| Image | PID | EPROCESS | ActiveProcessLinks | Flink | Blink |
| ----- | --- | -------- | ------------------ | ----- | ----- |
| svchost.exe | a08 | ffff958f8b9c22c0 | ffff958f`8b9c2708 | ffff958f`8b9a3508 | ffff958f`8f6114c8 |
| Calculator.exe | 17c8 | ffff958f8f611080 | ffff958f`8f6114c8 | 0xffff958f`8b9c2708 | 0xffff958f`8e4b3748 |
| ApplicationFrameHost.exe | 17b0 | ffff958f8e4b3300 | ffff958f`8e4b3748 | 0xffff958f`8f6114c8 | 0xffff958f`8e4be4c8  |

To manipulate these connections and remove the `Calculator.exe` process from it, we must change the following values

* Change the value of FLINK `svchost.exe` in **ffff958f\`‍8b9c2708** to FLINK `ApplicationFrameHost.exe` in **ffff958f\`8e4b3748**

* Change the value of BLINK `ApplicationFrameHost.exe` at **ffff958f\`8e4b3748+8** to FLINK `svchost.exe` at **ffff958f\`8b9c2708**.

> +8 because LIST_ENTRY has two FLINK/BLINK fields and each is 8 bytes

```bash
0: kd> eq ffff958f`8b9c2708 ffff958f`8e4b3748
0: kd> eq ffff958f`8e4b3748 + 8 ffff958f`8b9c2708
```

Once the memory is modified, I see that our target process is invisible

![](/assets/post/Dkom/hide.png)

## References

* [Manipulating ActiveProcessLinks to Hide Processes in Userland](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/manipulating-activeprocesslinks-to-unlink-processes-in-userland)
* [Understanding Windows DKOM(Direct Kernel Object Manipulation) techniques](https://nixhacker.com/understanding-windows-dkom-direct-kernel-object-manipulation-attacks-eprocess/)
* [When malware meets rootkits](https://www.virusbulletin.com/virusbulletin/2005/12/when-malware-meets-rootkits/)
* [blackhat - DKOM (Direct Kernel Object Manipulation)](https://www.blackhat.com/presentations/win-usa-04/bh-win-04-butler.pdf)
* [[windows] kernel internals](https://www.matteomalvica.com/minutes/windows_kernel/)
* [DKOM](https://www.cnblogs.com/houhaibushihai/p/10457338.html)
* [New Milestones for Deep Panda: Log4Shell and Digitally Signed Fire Chili Rootkits](https://www.fortinet.com/blog/threat-research/deep-panda-log4shell-fire-chili-rootkits)