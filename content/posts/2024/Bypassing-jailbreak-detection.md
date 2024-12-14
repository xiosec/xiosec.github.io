---
title: "Bypassing jailbreak detection mechanisms"
date: 2024-03-20T00:00:00+00:30
tags: ['security','reverse-engineering']
categories: ['security', 'reverse-engineering']
---

![](/assets/post/Jailbreak-Detection-Bypass/Banner.png)

In this post, I will talk about the challenges that this week with the mechanisms of `Jailbreak Detection` and how to bypass it. 

In much important software such as banking software, mechanisms such as Jailbreak Detection or debugging are incorporated to prevent software implementation.

The use of these types of mechanisms can have various reasons, such as preventing software lock bypassing by using debugging and dumping sensitive software information, etc.
For example, if you can bypass the lock screen of the software by debugging the software, you can access the information stored in it.

In the scenario that I have been dealing with all this time, I have to bypass the jailbreak detection mechanisms of an IOS software so that we can do various things such as traffic capture etc.

# Dynamic analysis

First, I captured a list of all function calls using frida-trace
```bash
# Get a list of app IDs
frida-ps -Ua
# Capture all calls
frida-trace -i '*'  -U -f com.app.example > calls.txt
```
At the very beginning of the list, I came across an item that caught my attention

```bash
IOSSecuritySuite.RuntimeHookChecker
IOSSecuritySuite.ReverseEngineeringToolsChecker
IOSSecuritySuite.ProxyChecker
IOSSecuritySuite.MSHookFunctionChecker
IOSSecuritySuite.JailbreakChecker
IOSSecuritySuite.IntegrityChecker
IOSSecuritySuite.IOSSecuritySuite
IOSSecuritySuite.SymbolFound
IOSSecuritySuite.FishHookChecker
IOSSecuritySuite.FileChecker
IOSSecuritySuite.EmulatorChecker
IOSSecuritySuite.DebuggerChecker
```

With a little search, I found out that the [IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite) library was used, as it is written in the description of this project, it is a library to prevent anti-tampering on the IOS platform.

This library has different parts that are explained in the table below each of them

| Class         | Description     |
|---------------|-----------------|
| [DebuggerChecker](https://github.com/securing/IOSSecuritySuite/blob/master/IOSSecuritySuite/DebuggerChecker.swift)  | This class has methods to check the status of the software, which determines whether the software is in debugging mode or not   |
| [EmulatorChecker](https://github.com/securing/IOSSecuritySuite/blob/master/IOSSecuritySuite/EmulatorChecker.swift)  | This class has methods to check the execution of the software in the Emulator environment  |
| [JailbreakChecker](https://github.com/securing/IOSSecuritySuite/blob/master/IOSSecuritySuite/JailbreakChecker.swift) | This class has methods to check read and write access to paths that only root has access to |
| [ReverseEngineeringToolsChecker](https://github.com/securing/IOSSecuritySuite/blob/master/IOSSecuritySuite/ReverseEngineeringToolsChecker.swift) | This class has methods to check for the presence of reverse engineering tools |

Using this script I collected all the classes related to IOSSecuritySuite:

```js
if (ObjC.available)
{
    for (var className in ObjC.classes)
    {
        if (ObjC.classes.hasOwnProperty(className) && className.includes("IOSSecuritySuite"))
        {
            console.log(className);
        }
    }
}
else
{
    console.log("Objective-C Runtime is not available!");
}
```
```bash
frida -l ./find-classes.js -U -f com.app.example

# output
IOSSecuritySuite.RuntimeHookChecker
IOSSecuritySuite.ReverseEngineeringToolsChecker
IOSSecuritySuite.ProxyChecker
IOSSecuritySuite.MSHookFunctionChecker
IOSSecuritySuite.JailbreakChecker
IOSSecuritySuite.IntegrityChecker
IOSSecuritySuite.IOSSecuritySuite
IOSSecuritySuiteXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXFishHookXXXX
IOSSecuritySuite.SymbolFound
IOSSecuritySuite.FishHookChecker
IOSSecuritySuite.FileChecker
IOSSecuritySuite.EmulatorChecker
IOSSecuritySuite.DebuggerChecker
```

At first, I looked for scripts ready to bypass IOSSecuritySuite, one of these scripts was [Darkprince-Jailbreak-Detection-Bypass](https://codeshare.frida.re/@sridharas04/darkprince-jailbreak-detection-bypass/), but this script only bypasses the JailbreakChecker class.

I decided to `hook` IOSSecuritySuite methods so that the inputs and outputs of each can be manipulated. For example, if the `amIDbugged` method returns `true`, I can manually change it to `false`, for example:

```js
Interceptor.attach(Module.findExportByName("IOSSecuritySuite", "amIDebugged"), {
  onEnter: function(args) {
    // Print out the function name and arguments
    console.log("amIDebugged has been called with arguments:");
    console.log("arg0: " + args[0] + " (context)");

    // Print out the call stack
    console.log("amIDebugged called from:\n" +
      Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress).join("\n") + "\n");
  },
  onLeave: function(retval) {
    // Print out the return value
    console.log("amIDebugged returned: " + retval);
    console.log("Set results to False");
    // Set the return value to 0x0 (False)
    retval.replace(0x0);
  }
});
```

There is a repository with the topic ["Jailbreak/Root Detection Bypass in Flutter"](https://github.com/CyberCX-STA/flutter-jailbreak-root-detection-bypass) which I followed, but then I faced a serious challenge.
I could not find almost any of the functions like `amIDebugge` with its original name, even the names with formats like `$s16IOSSecuritySuiteAAC13amIJailbrokenSbyFZ` did not exist. They probably created an obfuscation in the code so that we could not easily find the functions.

The names of some functions were in the following format: `IOSSecuritySuiteXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXFishHookXXXX`

But I did not find all the functions :)

# Static analysis
Next, I decided to decompile the project, the ipa files consist of different parts:
```bash
+ example.ipa
    |___Payload
        |___example.app
            |___en.lproj
            |___Frameworks # Libraries used
            |   |___libswiftCore.dylib
            |   |___...
            |____CodeSignature
            |___Info.plist
            |___example # The original binary
```

I decided to look for IOSSecuritySuite classes to patch any spots that used these classes.

I started the search from Constant values like strings, for example, in the `DebuggerChecker` class there is a string with this value `"Error occurred when calling sysctl(). The debugger check may not be reliable"` This can be a good thread to find the `DebuggerChecker` class be

Original source code: 

```swift
static func amIDebugged() -> Bool {
    var kinfo = kinfo_proc()
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
    var size = MemoryLayout<kinfo_proc>.stride
    let sysctlRet = sysctl(&mib, UInt32(mib.count), &kinfo, &size, nil, 0)
    
    if sysctlRet != 0 {
      print("Error occured when calling sysctl(). The debugger check may not be reliable")
    }
    
    return (kinfo.kp_proc.p_flag & P_TRACED) != 0
  }
```
The same part is decompiled:

|        |      |
| ------ | -----|
| ![](/assets/post/Jailbreak-Detection-Bypass/DebuggerChecker-amIDugged0.png) | ![](/assets/post/Jailbreak-Detection-Bypass/DebuggerChecker-amIDugged1.png) |

Other classes can be found in the same way:

```swift
internal class EmulatorChecker {
  static func amIRunInEmulator() -> Bool {
    return checkCompile() || checkRuntime()
  }

  private static func checkRuntime() -> Bool {
    return ProcessInfo().environment["SIMULATOR_DEVICE_NAME"] != nil
  }

  private static func checkCompile() -> Bool {
  #if targetEnvironment(simulator)
      return true
  #else
      return false
  #endif
  }
}
```

![](/assets/post/Jailbreak-Detection-Bypass/EmulatorChecker.png)

> [JailbreakChecker](https://github.com/securing/IOSSecuritySuite/blob/master/IOSSecuritySuite/JailbreakChecker.swift) class

![](/assets/post/Jailbreak-Detection-Bypass/JailbreakChecker.png)

> [ReverseEngineeringToolsChecker](https://github.com/securing/IOSSecuritySuite/blob/master/IOSSecuritySuite/ReverseEngineeringToolsChecker.swift) class

![](/assets/post/Jailbreak-Detection-Bypass/ReverseEngineeringToolsChecker.png)

Almost all classes can be found in this way, and we can debug it to check the correctness of this search.

# Debugging

There are different ways to debug iOS software:
 * [Debugging iOS Applications with IDA Pro](https://hex-rays.com/wp-content/static/tutorials/ios_debugger_primer2/ios_debugger_primer2.html)
 * [The missing guide to debug third party apps on iOS 12+](https://felipejfc.medium.com/the-ultimate-guide-for-live-debugging-apps-on-jailbroken-ios-12-4c5b48adf2fb)

We need Debugserver to start the debug environment.

>  [debugserver](https://iphonedev.wiki/Debugserver) is a console app that acts as server for remote gdb or lldb debugging. It is installed when a device is marked for development. It can be found in /Developer/usr/bin/debugserver. This is also the process invoked by Xcode to debug applications on the device. 


## Setup Debugserver

```bash
hdiutil attach /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/<VERSION>/DeveloperDiskImage.dmg

cp /Volumes/DeveloperDiskImage/usr/bin/debugserver ./
```

If you do not have access to xcode, you can download DeveloperDiskImage from this repository:
  * [DeveloperDiskImage](https://github.com/pdso/DeveloperDiskImage)

```bash
debugserver [<options>] host:<port> [<prog-name> <arg1> <arg2> ...]
```

options can be as follows: 

| Option           | Effect                                                                                   |
|------------------|------------------------------------------------------------------------------------------|
| -a process       | Attach debugserver to process. The process can be a pid or executable name.              |
| -d integer       | Assign the waitfor-duration.                                                             |
| -f ?             | ?                                                                                        |
| -g               | Turn on debugging.                                                                       |
| -i integer       | Assign the waitfor-interval.                                                             |
| -l filename      | Log to file. Set filename to stdout to log to standard output.                           |
| -t               | Use task ID instead of process ID.                                                       |
| -v               | Verbose.                                                                                 |
| -w ?             | ?                                                                                        |
| -x method        |                                                                                          |
| --launch=method  | How to launch the program. Can be one of:                                                |
|                  |   - auto: Auto-detect the best launch method to use.                                     |
|                  |   - fork: Launch program using fork(2) and exec(3).                                      |
|                  |   - posix: Launch program using posix_spawn(2).                                          |
|                  |   - backboard: Launch program via BackBoard Services.                                    |
|                  |                                                                                          |
|                  | The backboard option is only available in the closed-source version included in Xcode.   |
| --lockdown       | Obtain parameters from lockdown (?)                                                      |


> The vanilla debugserver lacks the task_for_pid() entitlement. For building and debugging your own apps on a properly provisioned device, this is not a problem; assuming your project and device are properly configured with your active iOS Developer Program, debugserver should have no trouble attaching to an app built and sent down to the device by Xcode. However, debugserver cannot attach to any other processes, including other apps from the App Store, due to lack of entitlement to allow task_for_pid(). An entitlement must be inserted into the binary to allow this. Note: The /Developer directory is actually a mounted read-only ramdisk. You cannot add any entitlements to the copy of debugserver installed there; it must be extracted to another directory and used from there. 


Save the following xml as entitlements.xml:

```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
      <key>com.apple.backboardd.debugapplications</key>
      <true/>
      <key>com.apple.backboardd.launchapplications</key>
      <true/>
      <key>com.apple.diagnosticd.diagnostic</key>
      <true/>
      <key>com.apple.frontboard.debugapplications</key>
      <true/>
      <key>com.apple.frontboard.launchapplications</key>
      <true/>
      <key>com.apple.security.network.client</key>
      <true/>
      <key>com.apple.security.network.server</key>
      <true/>
      <key>com.apple.springboard.debugapplications</key>
      <true/>
      <key>com.apple.system-task-ports</key>
      <true/>
      <key>get-task-allow</key>
      <true/>
      <key>platform-application</key>
      <true/>
      <key>run-unsigned-code</key>
      <true/>
      <key>task_for_pid-allow</key>
      <true/>
  </dict>
</plist>
```

Apply the entitlement with ldid:

```bash
ldid -Sentitlements.xml debugserver
```

> [ldid](https://iphonedev.wiki/Ldid) is a tool made by saurik for modifying a binary's entitlements easily. ldid also generates SHA1 and SHA256 hashes for the binary signature, so the iPhone kernel executes the binary. The package name in Cydia is "Link Identity Editor". 

`ldid -e` <binary> dumps the binary's entitlements.

`ldid -Sent.xml` <binary> sets the binary's entitlements, where `ent.xml` is the path to an entitlements file.

`ldid -S` <binary> `pseudo-signs` a binary with no entitlements. 

## Attaching to a process

On the device, type:

```bat
/usr/bin/debugserver 0.0.0.0:1234 -a "Files"

debugserver-@(#)PROGRAM:LLDB  PROJECT:lldb-1200.2.12
 for arm64.
Attaching to process Files...
Listening to port 1234 for a connection from 0.0.0.0...
```

To run an application in debug mode:
```bash
/usr/bin/debugserver -x backboard 0.0.0.0:4321 /private/var/containers/Bundle/Application/ID/example.app/example
```

This will launch the app and wait for remote troubleshooting.

## Debugging through USB instead of WiFi

After going through these steps, I found that debugging via WIFI is slow, an alternative solution is to debug via USB, for this you can use [libimobiledevice](https://github.com/libimobiledevice/libimobiledevice).

Unfortunately, libimobiledevice is not compiled for Windows. Download the compiled version for Windows from this [fork](https://github.com/L1ghtmann/libimobiledevice/releases/tag/suite-exe-6399052)

> [iproxy](https://man.archlinux.org/man/extra/libusbmuxd/iproxy.1.en) - A proxy that binds local TCP ports to be forwarded to the specified ports on a usbmux device.

EXAMPLES
  * `iproxy 2222:44`
    * Bind local TCP port `2222` and forward to port `44` of the first device connected via USB.

**SSH** proxying: 

```bash
iproxy.exe 2222:22

ssh root@localhost -p 2222
```

**debugserver** proxying:

```bash
iproxy.exe 1234:4321

/usr/bin/debugserver -x backboard 0.0.0.0:4321 /private/var/containers/Bundle/Application/ID/example.app/example
```

## Configuring the debugger

To connect IDA to debugserver, follow the steps below:

`Debugger`->`Select debugger…`​ and select `Remote iOS Debugger`:

![](/assets/post/Jailbreak-Detection-Bypass/SelectDebugger.png)

Now go to `Debugger`>`Process options...`>​ and ensure the following fields are set:

* **Hostname**: `localhost`
* **Port**: `1234`

![](/assets/post/Jailbreak-Detection-Bypass/ProcessOptions.png)

And  `Debugger`>`Attach to process...`>

![](/assets/post/Jailbreak-Detection-Bypass/AttachToProcess.png)

And finally it connects:

![](/assets/post/Jailbreak-Detection-Bypass/DebuggerAttached.png)

Next, I checked the classes I had found.

# Patching

After checking the points where `IOSSecuritySuite` classes are used, I came to the conclusion that it is enough to patch the points where IOSSecuritySuite functions are used.

For example, see the image below:

![](/assets/post/Jailbreak-Detection-Bypass/FunctionCall.png)

The `sub_10303D914` function is basically one of the methods of IOSSecuritySuite whose output specifies the jailbreak status.

If we go to `sub_10303D914`:

![](/assets/post/Jailbreak-Detection-Bypass/FunctionCall2.png)

It is clear that this is the [JailbreakChecker](https://github.com/securing/IOSSecuritySuite/blob/master/IOSSecuritySuite/JailbreakChecker.swift) class.

```swift
internal class JailbreakChecker {
...

  private static func checkFork() -> CheckResult {
      let pointerToFork = UnsafeMutableRawPointer(bitPattern: -2)
      let forkPtr = dlsym(pointerToFork, "fork")
      typealias ForkType = @convention(c) () -> pid_t
      let fork = unsafeBitCast(forkPtr, to: ForkType.self)
      let forkResult = fork()
      
      if forkResult >= 0 {
        if forkResult > 0 {
          kill(forkResult, SIGTERM)
        }
        return (false, "Fork was able to create a new process (sandbox violation)")
      }
      
      return (true, "")
  }

  private static func checkSuspiciousObjCClasses() -> CheckResult {
    if let shadowRulesetClass = objc_getClass("ShadowRuleset") as? NSObject.Type {
      let selector = Selector(("internalDictionary"))
      if class_getInstanceMethod(shadowRulesetClass, selector) != nil {
        return (false, "Shadow anti-anti-jailbreak detector detected :-)")
      }
    }
    return (true, "")
  }

...
}
```

We need to change code `BL sub_10303D914` to `NOP` to prevent `W0` register value from changing.

```asm
MOV             X20, X21
BL              sub_10303D914 # to NOP
MOV             X19, X2
TBZ             W0, #0, loc_103021650
```

Unfortunately, IDA does not support arm patching and you will be faced with the following message:

```
Sorry, this processor module doesn't support the assembler.
```

That's why I used [Keypatch](https://www.keystone-engine.org/keypatch/tutorial/).

>  Multi-architecture assembler for IDA Pro. Powered by Keystone Engine. 

First, you need to add the [Keypatch](https://github.com/keystone-engine/keypatch) plugin to IDA

Then we click on the desired instruction and press `Ctrl + Alt + K` keys

We change the value of the `Assembly field to NOP`

![](/assets/post/Jailbreak-Detection-Bypass/Patch.png)

After patching the instructions will change like this:

```asm
MOV             X20, X21
NOP                     ; Keypatch modified this from:
                        ;   BL sub_10303D914
MOV             X19, X2
TBZ             W0, #0, loc_103021650
```

After patching all parts, go to `Edit -> Patch Program -> Patches to input file` and save the file.

# Bypassing IOS Code Signatures

After patching the binary, IOS prevents the application from running because the application signature is invalid.

First, I tried to disable the signature verification function through `sysctl` and changing the value of `proc_enforce to 0`, but it seems that this method no longer works.

```bash
sysctl -w security.mac.proc_enforce=0
sysctl -w security.mac.vnode_enforce=0
```

![](/assets/post/Jailbreak-Detection-Bypass/Sysctl.png)

Next, I got acquainted with [AppSync Unified](https://cydia.akemi.ai/?page/ai.akemi.appsyncunified)

> AppSync Unified is a tweak that allows users to freely install ad-hoc signed, fakesigned, or unsigned IPA app packages on their iOS devices that iOS would otherwise consider invalid.

Follow the steps below to install AppSync:
  * Add [cydia.akemi.ai](https://cydia.akemi.ai) to `Cydia` sources
  * Search for the `AppSync Unified` package and then install it

Using the [ldid](https://iphonedev.wiki/Ldid) tool, we register a `fakesign` for our binary:

```bash
ldid -S example
```

Now we can run the program and that's it

# Links

* [https://github.com/securing/IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite)
* [https://iphonedev.wiki/Code_Signing](https://iphonedev.wiki/Code_Signing)
* [https://codeshare.frida.re/@sridharas04/darkprince-jailbreak-detection-bypass/](https://codeshare.frida.re/@sridharas04/darkprince-jailbreak-detection-bypass/)
* [https://github.com/CyberCX-STA/flutter-jailbreak-root-detection-bypass](https://github.com/CyberCX-STA/flutter-jailbreak-root-detection-bypass)
* [Jailbreak/Root Detection Bypass in Flutter](https://github.com/CyberCX-STA/flutter-jailbreak-root-detection-bypass)
* [Debugging iOS Applications with IDA Pro](https://hex-rays.com/wp-content/static/tutorials/ios_debugger_primer2/ios_debugger_primer2.html)
* [The missing guide to debug third party apps on iOS 12+](https://felipejfc.medium.com/the-ultimate-guide-for-live-debugging-apps-on-jailbroken-ios-12-4c5b48adf2fb)
* [https://iphonedev.wiki/Debugserver](https://iphonedev.wiki/Debugserver)
* [https://github.com/pdso/DeveloperDiskImage](https://github.com/pdso/DeveloperDiskImage)
* [https://iphonedev.wiki/Ldid](https://iphonedev.wiki/Ldid)
* [https://github.com/libimobiledevice/libimobiledevice](https://github.com/libimobiledevice/libimobiledevice)
* [https://man.archlinux.org/man/extra/libusbmuxd/iproxy.1.en](https://man.archlinux.org/man/extra/libusbmuxd/iproxy.1.en)
* [https://www.keystone-engine.org/keypatch/tutorial/](https://www.keystone-engine.org/keypatch/tutorial/)