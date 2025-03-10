**Program for sniff ip traffic on spicific interface + analysis ip data in the Linux system. Output to console or file.**

parameters for compiling:

compiling with buffering (output will be available after data collection + saving data to a file + analysis of IP addresses via the site [link](https://whatismyipaddress.com/))

compiling without buffering

**START**


```
git clone https://github.com/JOKKEU/ip_sniffer
cd ip_sniffer
if install.sh - non executable file: sudo chmod +x install.sh
./install.sh [(usually) --buffering | --no-buffering]
output:
[+] directory created
[+] moved to -> build
[+] gcc found
[+] program compiled
...
[sudo] password for ...: 
[+] program copied to /usr/local/bin
===== PROG INSTALLED =====
[+] run program (global scope) -> sniffer
[+] Usage: sniffer --help
```

sudo ./sniffer [iface index (example: 1] [id operation] [sniff time (sec)] [filename]

we launch chromedriver or firefoxdriver

example:

jokkeu@jokkeu-host:~/.cache/selenium/chromedriver/linux64/127.0.6533.119$ ./chromedriver 

python scrapping.py [browser (chrome or firefox)] [file name with initial data] [file name where to write data after processing]


Usage: sniffer --help.

ID operation 1 (simple all packet).

example:
```
jokkeu@jokkeu-host:~/Desktop/codes/ip_sniffer$ sudo sniffer 2 1 0 -
(INFO) iface index: 2 | id op: 1 | sniff time (sec): 0 | filename: -
...
(INFO) Receive packet: 1292 bytes
(INFO) Receive packet: 1292 bytes
(INFO) Receive packet: 511 bytes
(INFO) Receive packet: 158 bytes
(INFO) Receive packet: 67 bytes
(INFO) Receive packet: 162 bytes
(INFO) Receive packet: 67 bytes
(INFO) Receive packet: 67 bytes
(INFO) Receive packet: 67 bytes
(INFO) Receive packet: 71 bytes
(INFO) Receive packet: 73 bytes
(INFO) Receive packet: 1288 bytes
(INFO) Receive packet: 417 bytes
(INFO) Receive packet: 76 bytes
(INFO) Receive packet: 196 bytes
(INFO) Receive packet: 77 bytes
(INFO) Receive packet: 73 bytes
(INFO) Receive packet: 66 bytes
(INFO) Receive packet: 1466 bytes
(INFO) all receive bytes : 16855
(INFO) sniff time: 5
```
ID operation 2 (localnet + ip)(0.0.0.0 - from router).

example:
```
...
(INFO) =========
(INFO) Receive packet: 1506 bytes
(INFO) from ip - 0.0.0.0:0
(INFO) =========

(INFO) =========
(INFO) Receive packet: 1222 bytes
(INFO) from ip - 0.0.0.0:0
(INFO) =========

(INFO) ================================
(INFO) [0] source IP:PORT - 0.0.0.0:0
(INFO) Receive from this IP - 3276578 bytes
(INFO) ================================

(INFO) all receive bytes : 3276656
(INFO) sniff time: 8
```
ID operation 3 (TCP packet(global) + ip(sender)).

example:

```
(INFO) =========
(INFO) source		ip:port - 99.181.79.17:443
(INFO) destination      ip:port - 192.168.5.108:60286
(INFO) receive packet:  76 bytes
(INFO) =========

(INFO) =========
(INFO) source		ip:port - 99.181.79.17:443
(INFO) destination      ip:port - 192.168.5.108:60286
(INFO) receive packet:  52 bytes
(INFO) =========

(INFO) =========
(INFO) source		ip:port - 3.164.219.14:443
(INFO) destination      ip:port - 192.168.5.108:49166
(INFO) receive packet:  52 bytes
(INFO) =========

(INFO) ================================
(INFO) [0] source IP:PORT - 77.88.55.88:443
(INFO) Receive from this IP - 2152253 bytes
(INFO) ================================

(INFO) ================================
(INFO) [1] source IP:PORT - 3.164.230.110:443
(INFO) Receive from this IP - 29265 bytes
(INFO) ================================
...
(INFO) all receive bytes : 2185879
(INFO) sniff time: 12
```
ID operation 4 (UDP packet(global) + ip(sender)).

example:
```
...
(INFO) =========
(INFO) source		ip:port - 192.168.5.108:5353
(INFO) destination      ip:port - 224.0.0.251:5353
(INFO) receive packet:  172 bytes
(INFO) =========

(INFO) =========
(INFO) source		ip:port - 35.190.80.1:443
(INFO) destination      ip:port - 192.168.5.108:37165
(INFO) receive packet:  68 bytes
(INFO) =========

(INFO) ================================
(INFO) [0] source IP:PORT - 8.8.8.8:53
(INFO) Receive from this IP - 47811 bytes
(INFO) ================================

(INFO) ================================
(INFO) [1] source IP:PORT - 64.233.161.106:443
(INFO) Receive from this IP - 14161 bytes
(INFO) ================================

(INFO) ================================
(INFO) [2] source IP:PORT - 209.85.233.95:443
(INFO) Receive from this IP - 13464 bytes
(INFO) ================================

(INFO) ================================
(INFO) [3] source IP:PORT - 74.125.205.95:443
(INFO) Receive from this IP - 6859 bytes
(INFO) ================================

(INFO) ================================
(INFO) [4] source IP:PORT - 209.85.233.94:443
(INFO) Receive from this IP - 3733 bytes
(INFO) ================================

(INFO) ================================
(INFO) [5] source IP:PORT - 192.168.5.108:5353
(INFO) Receive from this IP - 569 bytes
(INFO) ================================

(INFO) ================================
(INFO) [6] source IP:PORT - 35.190.80.1:443
(INFO) Receive from this IP - 157 bytes
(INFO) ================================

(INFO) all receive bytes : 86822
(INFO) sniff time: 11
```

data in file
```
================================
[0] source IP:PORT - 188.114.98.224:443
Receive from this IP - 3514183 bytes
================================

================================
[1] source IP:PORT - 76.223.90.71:443
Receive from this IP - 531949 bytes
================================

================================
[2] source IP:PORT - 108.177.127.196:443
Receive from this IP - 236579 bytes
================================

================================
[3] source IP:PORT - 142.250.81.234:443
Receive from this IP - 189865 bytes
================================

================================
[4] source IP:PORT - 185.62.202.2:443
Receive from this IP - 130164 bytes
================================

================================
[5] source IP:PORT - 64.233.164.188:5228
Receive from this IP - 43508 bytes
================================

================================
[6] source IP:PORT - 213.180.204.186:443
Receive from this IP - 19762 bytes
================================

================================
[7] source IP:PORT - 64.233.164.18:443
Receive from this IP - 13283 bytes
================================

================================
[8] source IP:PORT - 74.125.205.198:443
Receive from this IP - 10445 bytes
================================
```
data after scrapping.py
```
IP: 188.114.98.224
Decimal:: 3161613024
Hostname:: 188.114.98.224
ASN:: 13335
ISP:: CloudFlare Inc.
Services:: Datacenter
Country:: United States
State/Region:: Indiana
City:: Francisco
Latitude:: 38.3333 (38° 19′ 59.84″ N)
Longitude:: -87.4471 (87° 26′ 49.50″ W)
Received bytes from this IP: 3514183


IP: 76.223.90.71
Decimal:: 1289706055
Hostname:: aaa409f8a5ec4adca.awsglobalaccelerator.com
ASN:: 16509
ISP:: Amazon.com Inc.
Services:: Datacenter
Country:: United States
State/Region:: Washington
City:: Seattle
Latitude:: 47.6043 (47° 36′ 15.51″ N)
Longitude:: -122.3298 (122° 19′ 47.43″ W)
Received bytes from this IP: 531949


IP: 108.177.127.196
Decimal:: 1823571908
Hostname:: el-in-f196.1e100.net
ASN:: 15169
ISP:: Google LLC
Services:: Datacenter
Country:: United States
State/Region:: California
City:: Mountain View
Latitude:: 37.4060 (37° 24′ 21.57″ N)
Longitude:: -122.0785 (122° 4′ 42.65″ W)
Received bytes from this IP: 236579
...
```
