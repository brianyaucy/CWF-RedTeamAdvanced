# Recon

- [Recon](#recon)
  - [Domain](#domain)
    - [nslookup](#nslookup)
    - [Sublist3r](#sublist3r)
  - [Service Enumerations](#service-enumerations)
    - [Web](#web)
      - [SSL Certificate](#ssl-certificate)
      - [Website](#website)
        - [/reg.php](#regphp)

## Domain

### nslookup
First do a NSLOOKUP on the domain `atomic-nuclear.site`:

```
nslookup -type=any atomic-nuclear.site
```

![picture 3](images/b839ed2a34e49d5b8ea9541c1e5e984e03ac0885900cb3f11fbfe598b6ecac73.png)  

<br/>

> IP Address:
192.168.8.3
<br/>

### Sublist3r

Use `Sublist3r` to enumerate & brute force the subdomains:

```
./sublist3r.py -b -d atomic-nuclear.site
```

![picture 95](images/8d7e690e09989eb10946ec495915dff994ead6c85194f3d687c1433d9650ca5f.png)  

```
atomic-nuclear.site
www.atomic-nuclear.site
git.atomic-nuclear.site
mail.atomic-nuclear.site
rds.atomic-nuclear.site
secretserver.atomic-nuclear.site
vdi.atomic-nuclear.site
```

---

## Service Enumerations
Use `nmap` to enumerate the service:
```
nmap -sV -sC -T4 -n -oN nmap-tcp-all.txt -p- --min-rate=1000 192.168.8.3
```


> Services:
> 
> - Web:
>   - tcp/80, tcp/443
>   - Apache/2.4.18
>   - Ubuntu
> 
> - Mail:
>   - tcp/25, tcp/110, tcp/143
>   - Dovecot
> 
> - SSH:
>   - tcp/22
> 
> - RDP:
>   - tcp/3389 (Filtered)

<br/>

### Web
#### SSL Certificate
Subject Alternative Name:

* atomic.site
* nuclear.site
* scada.local

Email:

* iyer@atomic-nuclear.site
* admin@atomic-nuclear.site

<br/>

#### Website

##### /reg.php

![picture 4](images/1cd6786d49db82c3c2c8282e2f98bc80d69ec1459c9c5802b9cd3f480c895565.png)  


Enter some information and use Burp to intercept the request:

![picture 5](images/9317040eeed9a48ea64754ae7ab1e5f5b95b877bd50bbb48126ee26b172eb7f7.png)  


The form is in XML format - could be tested against XXE injection.