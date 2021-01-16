# Scope

- [Scope](#scope)
- [Information Given](#information-given)
- [Objectives](#objectives)
- [Collection](#collection)
  - [Email](#email)
  - [Domains](#domains)
  - [Git](#git)
  - [Tech](#tech)
  - [Remote VDI](#remote-vdi)
  - [Network Diagram](#network-diagram)
  - [Credential](#credential)

# Information Given
```
atomic-nuclear.site
```

<br/>

# Objectives
1. Cause nuclear meltdown (detrimental-state)
2. Exfiltrate critical information on one of the air-gapped networks in the Lab environment.

<br/>

# Collection

## Email
* (SSL Cert Admin / Senior Scientist)
iyer@atomic-nuclear.site

```
UserName: iyer
Passwd: Iyer@123
Port: 110,143
```

* (SSL Cert Admin)
admin@atomic-nuclear.site
* (Senior Principal Scientist)
homi@atomic-nuclear.site

<br/>

## Domains

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

## Git
- [GitHub - atomic-nuclear/atomic-nuclear.github.io](https://github.com/atomic-nuclear/atomic-nuclear.github.io)
- [GitHub - atomic-nuclear/Scada-Repo](https://github.com/atomic-nuclear/Scada-Repo)
- [GitHub - atomic-nuclear/Critical-Information: This Repository Contains Sensitive Information Related to Nuclear Power Plant.](https://github.com/atomic-nuclear/Critical-Information)

<br/>

## Tech
* S3 bucket
  * Location: Unknown but Scientist should have access

<br/>

## Remote VDI
- Remote VDI Password:  `Sc!ent!st@1221`

<br/>

## Network Diagram
![picture 1](images/6b97ece5b0b5dac8cda58670220847b8abcbeb82e79a1131d08f72278ea7e5ab.png)  

<br/>

## Credential

```
# 192.168.8.3 (SSH)
iyer / Iyer@123
webadmin / WrongPassword
```

<br/>

```
# 10.1.3.1:1234 (Jenkins)
admin / admin
autoadmin / Jenk!nsADMIN
```

<br/>

```
# Windows Domain

operations.atomic.site
adm_domain / 3d15cb1141d579823f8bb08f1f23e316

atomic.site
Administrator / c49927a1eb5a335dfb681db95d3a45a2  
krbtgt / 5d14653ad207e053f2dbb9e3833b08bf

nuclear.site
iis_svc / B@DB!tch
```

<br/>

```
Jump-Server.nuclear.site (10.1.1.4)
jump-admin / B@DB!tch
```

<br/>

```
scada-host.scada.local (10.2.1.1)
Administrator / SCADAAdmin!@#$%
```