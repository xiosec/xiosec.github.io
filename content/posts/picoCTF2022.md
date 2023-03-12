---
title: picoCTF 2022
date: 2022-04-13 18:09:09
tags: ['voynich', 'CTF']
categories: ['CTF', 'security', 'writeup']
---

picoCTF is the largest cybersecurity hacking competition for middle and high school students. Participants 13 years and older of all skill levels are encouraged to compete. Competitors must reverse-engineer, break, hack, decrypt, and think creatively and critically to solve the challenges and capture the digital flags.

[CTF Time](https://ctftime.org/event/1578)

## Forensics 

### St3g0

 ```bash
zsteg -a -v ./pico.flag.png | grep picoCTF
```
```
b1,rgb,lsb,xy       .. text: "picoCTF{7h3r3_15_n0_5p00n_1b8d71db}$t3g0"
    00000000: 70 69 63 6f 43 54 46 7b  37 68 33 72 33 5f 31 35  |picoCTF{7h3r3_15|
```

:::tip
As a result, the flag is located at b1,rgb,lsb,xy, where rgb means it uses RGB channel, lsb means least significant bit comes first, and xy means pixel iteration order is from left to right.
:::

### Redaction gone wrong

In the PDF, select the highlighted part and copy it. Paste it in a text file to see the
```
picoCTF{C4n_Y0u_S33_m3_fully}
```

### File types

The point of this challenge is the type of files, you should check the file type every time with the file command

```bash
$ file Flag.pdf
   | 
   |-> shell archive text

$ cp Flag.pdf Flag.sh
$ chmod +x Flag.sh
$ Flag.sh
   |
   |-> x - created lock directory _sh00046.
       x - SKIPPING flag (file already exists)
       x - removed lock directory _sh00046.

# After executing, a file called flag was generated
$ binwalk -e flag

# created a new folder called _flag.extracted
$ binwalk -e 64

$ lzip -d -k flag

$ lz4 -d flag.out flag2.out

$ lzma -d -k flag2.lzma

$ lzop -d -k flag2.lzop -o flag3

$ lzip -d -k flag3

$ xz -d -k flag4.xz

echo 7069636f4354467b66316c656e406d335f6d406e3170756c407431306e5f6630725f3062326375723137795f33343765616536357d0a | xxd -r -p

```
> picoCTF{f1len@m3_m@n1pul@t10n_f0r_0b2cur17y_347eae65}

---

## Reverse Engineering

### file-run1
We just need to execute the executable to obtain the flag.
> picoCTF{U51N6_Y0Ur_F1r57_F113_9bc52b6b}

### file-run2
This challenge provided an executable.

> picoCTF{F1r57_4rgum3n7_be0714da}

### GDB Test Drive

```bash
$ chmod +x gdbme
$ gdb gdbme
(gdb) layout asm
(gdb) break *(main+99)
(gdb) run
(gdb) jump *(main+104)

gdb➤  jump *(main+104)
Continuing at 0x800132f.
picoCTF{d3bugg3r_dr1v3_72bd8355}
[Inferior 1 (process 543) exited normally]
```
> picoCTF{d3bugg3r_dr1v3_197c378a}

### patchme.py

If you look at the code, you will see that the password is hard coded
```python
def level_1_pw_check():
    user_pw = input("Please enter correct password for flag: ")
    if( user_pw == "ak98" + \
                   "-=90" + \
                   "adfjhgj321" + \
                   "sleuth9000"):
        print("Welcome back... your flag, user:")
        decryption = str_xor(flag_enc.decode(), "utilitarian")
        print(decryption)
        return
    print("That password is incorrect")
```

The password is: ak98-=90adfjhgj321sleuth9000

> picoCTF{p47ch1ng_l1f3_h4ck_c4a4688b}

### Safe Opener
See this part of the code:
```java
public static boolean openSafe(String password) {
        String encodedkey = "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz";
        
        if (password.equals(encodedkey)) {
            System.out.println("Sesame open");
            return true;
        }
        else {
            System.out.println("Password is incorrect\n");
            return false;
        }
    }
```

Again, the password key is hardcoded with base64 encoding. We just need to base64 decode it:
```bash
echo -n "cGwzYXMzX2wzdF9tM18xbnQwX3RoM19zYWYz" | base64 -d
```

> picoCTF{pl3as3_l3t_m3_1nt0_th3_saf3}

### bloat.py

This section checks the password:
```python
def arg133(arg432):
  if arg432 == a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68]:
    return True
  else:
    print(a[51]+a[71]+a[64]+a[83]+a[94]+a[79]+a[64]+a[82]+a[82]+a[86]+a[78]+\
a[81]+a[67]+a[94]+a[72]+a[82]+a[94]+a[72]+a[77]+a[66]+a[78]+a[81]+\
a[81]+a[68]+a[66]+a[83])
    sys.exit(0)
    return False
```

These characters are basically passwords:
```python
arg432 == a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68]
```
Add this line to the code
```python
print(a[71]+a[64]+a[79]+a[79]+a[88]+a[66]+a[71]+a[64]+a[77]+a[66]+a[68])
```
password : happychance

> picoCTF{d30bfu5c4710n_f7w_b8062eec}

### Fresh Java
```java
    .
    .
    .
    if (string.charAt(3) != 'o') {
        System.out.println("Invalid key");
        return;
    }
    if (string.charAt(2) != 'c') {
        System.out.println("Invalid key");
        return;
    }
    if (string.charAt(1) != 'i') {
        System.out.println("Invalid key");
        return;
    }
    if (string.charAt(0) != 'p') {
        System.out.println("Invalid key");
        return;
    }
```

Again, hardcoded key, by concating it, we will get the flag.

> picoCTF{700l1ng_r3qu1r3d_738cac89}

### Bbbbloat

From the decompiled code, we can see after it was for favorite number, it performs some kind of comparison
```c
if (local_48 == 549255) {
	__s = (char *)FUN_00101249(0,&local_38);
	fputs(__s,stdout);
	putchar(10);
	free(__s);
}
```
```bash
./bbbbloat
What's my favorite number? 549255
picoCTF{cu7_7h3_bl047_695036e3}
```

> picoCTF{cu7_7h3_bl047_695036e3}

### unpackme
The binary file was packed by using UPX, to unpack it, run the command below
```bash
upx -d ./unpackme-upx
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   1002408 <-    439736   43.87%   linux/amd64   unpackme-upx

Unpacked 1 file.
```
Like the previous challenge, From the decompiled
```c
if (local_44 == 754635) {
	local_40 = (char *)rotate_encrypt(0,&local_38);
	fputs(local_40,(FILE *)stdout);
	putchar(10);
	free(local_40);
}
```

> picoCTF{up><_m3_f7w_77ad107e}

### Keygenme

```c
strcpy(half_flag, "picoCTF{br1ng_y0ur_0wn_k3y_");// half_flag_len = 27
                                                // flag_len = 37
                                                // 
  strcpy(v8, "}");
  strlen(half_flag);                            // 27
  MD5();
  strlen(v8);                                   // 1
  MD5();
```
From the code above, we can see half of the flag

```
picoCTF{br1ng_y0ur_0wn_k3y_
```
```c
full_flag[59] = half_flag[45];
full_flag[60] = half_flag[50];
full_flag[61] = v10;
full_flag[62] = half_flag[33];
full_flag[63] = half_flag[46];
full_flag[64] = half_flag[56];
full_flag[65] = half_flag[58];
full_flag[66] = v10;
full_flag[67] = v8[0];
```
The value of each of these index in memory is equal to
```
0x7d
0x39
0x38
0x33
0x36
0x63
0x64
0x38
```

using Python to concat it
```python
n = [0x7d, 0x39, 0x38, 0x33, 0x36, 0x63, 0x64 ,0x38]
n.reverse()
"".join(list(map(lambda x:chr(x), n)))

# 8dc6389}
```
> picoCTF{br1ng_y0ur_0wn_k3y_19836cd8}
