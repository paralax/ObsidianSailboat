# ObsidianSailboat
Nmap and NSE command line wrapper

# the vision
A tool that integrates a bunch of NSE scripts together to build a picture of a host that we can reason over and discover various properties. I got sick of either losing data about hosts (dropping it on the floor), wrapping glue code to bridge from one tool to another, and the tons of boilerplate calls I make to various NSE scripts.

This is designed to couple to tools like recon-ng, SET, metasploit, and w3af for discovery, mapping, and footprinting. 

# usage 

The commands borrow models like set, setg, and the like from Metasploit.

| Command | Description | Example |
| --------|-------------|---------|
| add | Add a host by IP or hostname | `add 1.2.3.4` |
| back | Return to the top level command | `back` |
| banner | Prints a random OSail banner | `banner` |
| detail | Get detailed info about a host | `detail 1.2.3.4` |
| exit | Exits OSail | `exit` |
| getf |  Get the module's Nmap flags | `getf` |
| getg | Get global option information | `getg` |
| help | List available commands with "help" or detailed help with "help cmd". | `help` |
| hosts | Show info about known hosts | `hosts` |
| import | Import an Nmap XML file and add information | `import nmap_output.xml` |
| ports | Show known hosts, ports, and information | `ports`, `ports state open`, `ports 1.2.3.4`, `ports port 22` |
| rescan | Rescans NSE directory | `rescan` |
| restore | Replays a session from a savefile | `restore mycmds.txt` |
| run | Runs the selected module | `run` |
| search | Searches modules for the argument | `search tftp` |
| set | Set a module specific option | `set RHOST 1.2.3.0/24` |
| setf | Set a global flag | `setf -P0` |
| setg | Set a global option | `setg --scan-delay 99` |
| show | Show information about modules or results: 'vulns', 'info', 'description', 'results' | `show info` |
| sleep | Sleep for N seconds | `sleep 2` |
| unset | Unset the option | `unset RHOST` |
| unsetf | Unsets a flag | `unsetf -R` |
| use | Use the selected module | `use intrusive/tftp/tftp-enum` |
| workspace | Show, change, or create a workspace | `workspace add customer`, `workspace select customer` |

Hosts are defined in the `RHOST` option, much like Metasploit. Like Metasploit and Recon-ng, if you see (or set) the option "default" it will enumerate targets from the hosts it's identified. 

Often I will use the host discovery modules - aka `discovery/ping/host-discovery` or `discovery/tcp/masscan-discovery` - and set `RHOST` to a CIDR network and let those modules run and find live hosts. Then future modules I choose - e.g. `discovery/banner` - will scan only those live hosts. 

# requirements

Because ObsidianSailboat wraps [Nmap](https://nmap.org/), you must have Nmap installed. You can see more about the large body of NSE scripts available at the [NSEDoc](https://nmap.org/nsedoc/) site. 

Optionally you can install [Masscan](https://github.com/robertdavidgraham/masscan) for high throughput wide area host discovery. I use this when doing host enumeration, for instance. 

# preparing and installing

I run OSail on Kali Linux, which has Nmap and Masscan installed. 

You'll have to install the dotnet core, and while we're at it we'll install `aptitude` as well. You have to add a couple of dependencies, add the MS repo info, and then install the dotnet-sdk package:

	$ wget http://mirrors.edge.kernel.org/ubuntu/pool/main/i/icu/libicu60_60.2-6ubuntu1_amd64.deb
	$ sudo dpkg -i libicu60_60.2-6ubuntu1_amd64.deb
	$ wget http://mirrors.edge.kernel.org/ubuntu/pool/main/o/openssl/libssl1.0.0_1.0.2g-1ubuntu4_amd64.deb
	$ sudo dpkg -i libssl1.0.0_1.0.2g-1ubuntu4_amd64.deb
	$ wget -q https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb
	$ sudo dpkg -i packages-microsoft-prod.deb
	$ sudo apt-get install aptitude
	$ sudo aptitude install dotnet-sdk-2.2

# building

To install dependencies and build use [dotnet core](https://docs.microsoft.com/en-us/dotnet/core/tools/index?tabs=netcore2x) and run:

    $ dotnet restore

To run use:

    $ dotnet run

# example session

	[+] ObsidianSailboat starting up ...

	    O))))     O))                     O))                        O)) O)                O))O))                            O))
	  O))    O))  O))              O)     O)) O)                   O))    O))           O) O))O))                            O))
	O))        O))O))       O))))         O))      O))    O)) O))   O))         O))        O))O))         O))       O))    O)O) O)
	O))        O))O)) O))  O))    O)) O)) O))O)) O))  O))  O))  O))   O))     O))  O)) O)) O))O)) O))   O))  O))  O))  O))   O))
	O))        O))O))   O))  O))) O))O)   O))O))O))   O))  O))  O))      O)) O))   O)) O)) O))O))   O))O))    O))O))   O))   O))
	  O))     O)) O))   O))    O))O))O)   O))O))O))   O))  O))  O))O))    O))O))   O)) O)) O))O))   O)) O))  O)) O))   O))   O))
	    O))))     O)) O))  O)) O))O)) O)) O))O))  O)) O)))O)))  O))  O)) O)    O)) O)))O))O)))O)) O))     O))      O)) O)))   O))



	[+] Welcome to ObsidianSailboat
	[+] Loaded 568 modules
	osail > use discovery/tcp/
	discovery/tcp/connect           discovery/tcp/service-discovery discovery/tcp/syn
	osail > use discovery/tcp/service-discovery
	osail default(tcp-service-discovery)> set RHOST 159.89.225.14
	osail default(tcp-service-discovery)> unset RPORT
	osail default(tcp-service-discovery)> show info
	      Name: tcp-service-discovery
	    Module: /usr/bin/nmap
	 Author(s): Fyodor
	   License: Nmap--See https://nmap.org/book/man-legal.html
	Categories: default, safe, version, discovery

	Options:
	  Name                      Current Setting    Description
	  ----                      ---------------    -----------
	  --version-intensity       2                  Set from 0 (light) to 9 (try all probes)
	  RHOST                     159.89.225.14      The target address
	  RPORT                                        The target port

	Description:
	 Probe open ports to determine service/version info

	osail default(tcp-service-discovery)> run
	[*] /usr/bin/nmap  -sV -A -oX - --version-intensity=2 --host-timeout=10 --dns-servers=8.8.8.8 --max-retries=10 --max-scan-delay=0 --min-parallelism=1 --scan-delay=0 --max-parallelism=100 159.89.225.14

	[+] Nmap done at Sat Mar 17 01:08:13 2018; 1 IP address (1 host up) scanned in 7.85 seconds
	[+] 159.89.225.14
	[+] Anonymous FTP login allowed (FTP code 230)
	-rw-r--r--    1 0        0           37412 Feb 17 16:49 1337
	-rw-r--r--    1 0        0           37411 Feb 17 16:49 bazooka
	-rw-r--r--    1 0        0           37422 Feb 17 21:09 bot.php
	-rw-r--r--    1 0        0           38192 Feb 17 16:49 cyber
	-rw-r--r--    1 0        0            2117 Feb 17 16:49 cyberinfo
	-rw-r--r--    1 0        0           37421 Feb 17 16:49 cybernetikus
	-rw-r--r--    1 0        0           37415 Feb 25 20:25 duck
	-rw-r--r--    1 0        0           39045 Feb 25 20:16 duckperlbot
	-rw-r--r--    1 0        0          668568 Feb 17 16:49 miner
	-rw-r--r--    1 0        0           38164 Feb 20 17:19 pwlamea
	-rw-r--r--    1 0        0           39082 Feb 28 10:59 salpa
	-rw-r--r--    1 0        0           37406 Feb 17 16:49 xmlrpc
	[+] bounce working!
	[+]
	  STAT:
	FTP server status:
	     Connected to ::ffff:x.x.x.x
	     Logged in as ftp
	     TYPE: ASCII
	     No session bandwidth limit
	     Session timeout in seconds is 300
	     Control connection is plain text
	     Data connections will be plain text
	     At session startup, client count was 16
	     vsFTPd 3.0.3 - secure, fast, stable
	End of status
	[+]
	  2048 32:9c:3f:17:95:6c:3f:6e:3c:ee:c6:f7:9b:d8:00:56 (RSA)
	  256 43:ff:5a:8c:3a:06:5c:8a:37:1a:7c:69:6b:d5:a2:40 (ECDSA)
	  256 a9:c8:ca:d7:97:50:47:aa:fa:ed:51:46:2e:af:ba:f9 (ED25519)
	osail default(tcp-service-discovery)>
	osail default(tcp-service-discovery)> hosts 159.89.225.14
	    Host                 Hostname
	    ----                 --------
	    159.89.225.14
	    Port 25/tcp (smtp): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 21/tcp (ftp): 	State: open
	        CPE
	           cpe:/a:vsftpd:vsftpd:3.0.3
	        Analysis
	           ftp-syst
	               STAT=
	FTP server status:
	     Connected to ::ffff:x.x.x.x
	     Logged in as ftp
	     TYPE: ASCII
	     No session bandwidth limit
	     Session timeout in seconds is 300
	     Control connection is plain text
	     Data connections will be plain text
	     At session startup, client count was 16
	     vsFTPd 3.0.3 - secure, fast, stable
	End of status
	    Port 22/tcp (unknown): 	State: open
	        CPE
	           cpe:/a:openbsd:openssh:7.2p2
	        Analysis
	           ssh-hostkey
	               a9c8cad7975047aafaed51462eafbaf9
	               ecdsa-sha2-nistp256
	               329c3f17956c3f6e3ceec6f79bd80056
	               ssh-ed25519
	               43ff5a8c3a065c8a371a7c696bd5a240
	               AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCVPtJldY/DLYM/YF33JwtJxAexVvfngTPQ7AC/yhJe89sbilgT1QbjdMTiUiaZzdsOGcUIEmi0Er/Weqewhk7E=
	               256
	               AAAAB3NzaC1yc2EAAAADAQABAAABAQC8XmX6NUku0CcKR6F5tfOnKRkw1ndqmjLRMniykYj4vVjLnpUlxokTdUCi/KR09H1z8kNk3869xW7nu9fN0vhMuOhmCBjKBTWiWzMd7s6JWrzH0ArKQsT9+UpOrf74n3LoxtgmuXmjW8Am/FW7spsFb/b8e/s1s/Gtzs0aVQ+KuRr6Qr9dz3j6c/dLZLP3sKKBFjiIOHjPputPO/17x8Hhs92fhHc5LNtoGKd4Te7duCt+HlJ7mXgq4uPRuboguY3dtfDVdBUoOsOjkXLObyWjk8e534sKhpP8AWgw6txiTHr+DvBMyeU8BtzMjdsWAT7G6yyq84uQCb5TIAhY2/z3
	               2048.0
	               AAAAC3NzaC1lZDI1NTE5AAAAINCNGhPoag3xFg0X2gsxDkQy/xkye2fZ7yHVYYXpqQ3y
	               ssh-rsa
	               a9c8cad7975047aafaed51462eafbaf9
	               ecdsa-sha2-nistp256
	               329c3f17956c3f6e3ceec6f79bd80056
	               ssh-ed25519
	               43ff5a8c3a065c8a371a7c696bd5a240
	               AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCVPtJldY/DLYM/YF33JwtJxAexVvfngTPQ7AC/yhJe89sbilgT1QbjdMTiUiaZzdsOGcUIEmi0Er/Weqewhk7E=
	               256
	               AAAAB3NzaC1yc2EAAAADAQABAAABAQC8XmX6NUku0CcKR6F5tfOnKRkw1ndqmjLRMniykYj4vVjLnpUlxokTdUCi/KR09H1z8kNk3869xW7nu9fN0vhMuOhmCBjKBTWiWzMd7s6JWrzH0ArKQsT9+UpOrf74n3LoxtgmuXmjW8Am/FW7spsFb/b8e/s1s/Gtzs0aVQ+KuRr6Qr9dz3j6c/dLZLP3sKKBFjiIOHjPputPO/17x8Hhs92fhHc5LNtoGKd4Te7duCt+HlJ7mXgq4uPRuboguY3dtfDVdBUoOsOjkXLObyWjk8e534sKhpP8AWgw6txiTHr+DvBMyeU8BtzMjdsWAT7G6yyq84uQCb5TIAhY2/z3
	               2048.0
	               AAAAC3NzaC1lZDI1NTE5AAAAINCNGhPoag3xFg0X2gsxDkQy/xkye2fZ7yHVYYXpqQ3y
	               ssh-rsa
	    Port 554/tcp (tcpwrapped): 	State: open
	        CPE
	           None
	        Analysis
	    Port 7070/tcp (tcpwrapped): 	State: open
	        CPE
	           None
	        Analysis
	    Port 445/tcp (microsoft-ds): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 135/tcp (msrpc): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 139/tcp (netbios-ssn): 	State: filtered
	        CPE
	           None
	        Analysis
	osail default(tcp-service-discovery)> ports 159.89.225.14
	[-] Error, expected filter field
	osail default(tcp-service-discovery)> ports
	host  port  state
	osail default(tcp-service-discovery)> ports hos
	osail default(tcp-service-discovery)> ports host 159.89.225.14
	    Host                 Hostname                                            Proto       Port State            Service    CPE
	    ----                 --------                                            -----       ---- -----            -------    ---
	    159.89.225.14                                                              tcp        135 filtered         msrpc
	    159.89.225.14                                                              tcp        139 filtered         netbios-ssn
	    159.89.225.14                                                              tcp         21 open             ftp        cpe:/a:vsftpd:vsftpd:3.0.3
	    159.89.225.14                                                              tcp         22 open             ssh        cpe:/o:linux:linux_kernel
	    159.89.225.14                                                              tcp         22 open             ssh        cpe:/a:openbsd:openssh:7.2p2
	    159.89.225.14                                                              tcp         25 filtered         smtp
	    159.89.225.14                                                              tcp        445 filtered         microsoft-ds
	    159.89.225.14                                                              tcp        554 open             tcpwrapped
	    159.89.225.14                                                              tcp       7070 open             tcpwrapped
	osail default(tcp-service-discovery)> search vsftp
	exploit/ftp/vsftpd-backdoor            Tests for the presence of the vsFTPd 2.3.4 backdoor reporte
	intrusive/ftp/vsftpd-backdoor          Tests for the presence of the vsFTPd 2.3.4 backdoor reporte
	malware/ftp/vsftpd-backdoor            Tests for the presence of the vsFTPd 2.3.4 backdoor reporte
	vuln/ftp/vsftpd-backdoor               Tests for the presence of the vsFTPd 2.3.4 backdoor reporte
	osail default(tcp-service-discovery)> use exploit/ftp/vsftpd-backdoor
	osail vuln(ftp-vsftpd-backdoor)> show info
	      Name: ftp-vsftpd-backdoor
	    Module: /usr/share/nmap/scripts/ftp-vsftpd-backdoor.nse
	 Author(s): Daniel Miller
	   License: Same as Nmap--See https://nmap.org/book/man-legal.html
	Categories: vuln, malware, intrusive, exploit

	Options:
	  Name                      Current Setting    Description
	  ----                      ---------------    -----------
	  RHOST                     default            The target address
	  RPORT                     80                 The target port
	  ftp-vsftpd-backdoor.cmd                      Command to execute in shell

	Description:
	  Tests for the presence of the vsFTPd 2.3.4 backdoor reported on
	  2011-07-04 (CVE-2011-2523). This script attempts to exploit the
	  backdoor using the innocuous <code>id</code> command by default, but
	  that can be changed with the <code>exploit.cmd</code> or <code>ftp-
	  vsftpd-backdoor.cmd</code> script arguments.  References:  *
	  http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-
	  download-backdoored.html * https://github.com/rapid7/metasploit-fram
	  ework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb *
	  http://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=CVE-2011-2523

	osail vuln(ftp-vsftpd-backdoor)> set RHOST  159.89.225.14
	osail vuln(ftp-vsftpd-backdoor)> set RPORT 21
	osail vuln(ftp-vsftpd-backdoor)> set ftp-vsftpd-backdoor.cmd ls
	osail vuln(ftp-vsftpd-backdoor)> run
	[*] /usr/bin/nmap -p 21 -A -oX - --script ftp-vsftpd-backdoor --script-args "ftp-vsftpd-backdoor.cmd=ls" --host-timeout=10 --dns-servers=8.8.8.8 --max-retries=10 --max-scan-delay=0 --min-parallelism=1 --scan-delay=0 --max-parallelism=100 159.89.225.14
	[+] Nmap done at Sat Mar 17 01:09:47 2018; 1 IP address (1 host up) scanned in 0.90 seconds
	[+] 159.89.225.14
	osail vuln(ftp-vsftpd-backdoor)> hosts 159.89.225.14
	    Host                 Hostname
	    ----                 --------
	    159.89.225.14
	    Port 25/tcp (smtp): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 21/tcp (unknown): 	State: open
	        CPE
	           cpe:/a:vsftpd:vsftpd:3.0.3
	        Analysis
	           ftp-syst
	               STAT=
	FTP server status:
	     Connected to ::ffff:x.x.x.x
	     Logged in as ftp
	     TYPE: ASCII
	     No session bandwidth limit
	     Session timeout in seconds is 300
	     Control connection is plain text
	     Data connections will be plain text
	     At session startup, client count was 16
	     vsFTPd 3.0.3 - secure, fast, stable
	End of status
	    Port 22/tcp (unknown): 	State: open
	        CPE
	           cpe:/a:openbsd:openssh:7.2p2
	        Analysis
	           ssh-hostkey
	               a9c8cad7975047aafaed51462eafbaf9
	               ecdsa-sha2-nistp256
	               329c3f17956c3f6e3ceec6f79bd80056
	               ssh-ed25519
	               43ff5a8c3a065c8a371a7c696bd5a240
	               AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCVPtJldY/DLYM/YF33JwtJxAexVvfngTPQ7AC/yhJe89sbilgT1QbjdMTiUiaZzdsOGcUIEmi0Er/Weqewhk7E=
	               256
	               AAAAB3NzaC1yc2EAAAADAQABAAABAQC8XmX6NUku0CcKR6F5tfOnKRkw1ndqmjLRMniykYj4vVjLnpUlxokTdUCi/KR09H1z8kNk3869xW7nu9fN0vhMuOhmCBjKBTWiWzMd7s6JWrzH0ArKQsT9+UpOrf74n3LoxtgmuXmjW8Am/FW7spsFb/b8e/s1s/Gtzs0aVQ+KuRr6Qr9dz3j6c/dLZLP3sKKBFjiIOHjPputPO/17x8Hhs92fhHc5LNtoGKd4Te7duCt+HlJ7mXgq4uPRuboguY3dtfDVdBUoOsOjkXLObyWjk8e534sKhpP8AWgw6txiTHr+DvBMyeU8BtzMjdsWAT7G6yyq84uQCb5TIAhY2/z3
	               2048.0
	               AAAAC3NzaC1lZDI1NTE5AAAAINCNGhPoag3xFg0X2gsxDkQy/xkye2fZ7yHVYYXpqQ3y
	               ssh-rsa
	               a9c8cad7975047aafaed51462eafbaf9
	               ecdsa-sha2-nistp256
	               329c3f17956c3f6e3ceec6f79bd80056
	               ssh-ed25519
	               43ff5a8c3a065c8a371a7c696bd5a240
	               AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCVPtJldY/DLYM/YF33JwtJxAexVvfngTPQ7AC/yhJe89sbilgT1QbjdMTiUiaZzdsOGcUIEmi0Er/Weqewhk7E=
	               256
	               AAAAB3NzaC1yc2EAAAADAQABAAABAQC8XmX6NUku0CcKR6F5tfOnKRkw1ndqmjLRMniykYj4vVjLnpUlxokTdUCi/KR09H1z8kNk3869xW7nu9fN0vhMuOhmCBjKBTWiWzMd7s6JWrzH0ArKQsT9+UpOrf74n3LoxtgmuXmjW8Am/FW7spsFb/b8e/s1s/Gtzs0aVQ+KuRr6Qr9dz3j6c/dLZLP3sKKBFjiIOHjPputPO/17x8Hhs92fhHc5LNtoGKd4Te7duCt+HlJ7mXgq4uPRuboguY3dtfDVdBUoOsOjkXLObyWjk8e534sKhpP8AWgw6txiTHr+DvBMyeU8BtzMjdsWAT7G6yyq84uQCb5TIAhY2/z3
	               2048.0
	               AAAAC3NzaC1lZDI1NTE5AAAAINCNGhPoag3xFg0X2gsxDkQy/xkye2fZ7yHVYYXpqQ3y
	               ssh-rsa
	    Port 554/tcp (tcpwrapped): 	State: open
	        CPE
	           None
	        Analysis
	    Port 7070/tcp (tcpwrapped): 	State: open
	        CPE
	           None
	        Analysis
	    Port 445/tcp (microsoft-ds): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 135/tcp (msrpc): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 139/tcp (netbios-ssn): 	State: filtered
	        CPE
	           None
	        Analysis
	osail vuln(ftp-vsftpd-backdoor)> search ssh
	auth/ssh/auth-methods                  Returns authentication methods that a SSH server supports.
	auth/ssh/publickey-acceptance          This script takes a table of paths to private keys, passphr
	default/ssh/hostkey                    Shows SSH hostkeys.  Shows the target SSH server's key fing
	default/sshv1                          Checks if an SSH server supports the obsolete and less secu
	discovery/ssh/hostkey                  Shows SSH hostkeys.  Shows the target SSH server's key fing
	discovery/ssh2-enum-algos              Reports the number of algorithms (for encryption, compressi
	intrusive/ssh/auth-methods             Returns authentication methods that a SSH server supports.
	intrusive/ssh/publickey-acceptance     This script takes a table of paths to private keys, passphr
	safe/duplicates                        Attempts to discover multihomed systems by analysing and co
	safe/rsa-vuln-roca                     Detects RSA keys vulnerable to Return Of Coppersmith Attack
	safe/ssh/brute                         Performs brute-force password guessing against ssh servers.
	safe/ssh/hostkey                       Shows SSH hostkeys.  Shows the target SSH server's key fing
	safe/ssh/run                           Runs remote command on ssh server and returns command outpu
	safe/ssh2-enum-algos                   Reports the number of algorithms (for encryption, compressi
	safe/sshv1                             Checks if an SSH server supports the obsolete and less secu
	safe/unusual-port                      Compares the detected service on a port against the expecte
	vuln/rsa-vuln-roca                     Detects RSA keys vulnerable to Return Of Coppersmith Attack
	osail vuln(ftp-vsftpd-backdoor)> use auth/ssh/auth-methods
	osail intrusive(ssh-auth-methods)> use auth/set RHOST  159.89.225.14
	osail intrusive(ssh-auth-methods)> run
	[*] /usr/bin/nmap -p 22 -A -oX - --script ssh-auth-methods --script-args "" --host-timeout=10 --dns-servers=8.8.8.8 --max-retries=10 --max-scan-delay=0 --min-parallelism=1 --scan-delay=0 --max-parallelism=100 159.89.225.14
	[+] Nmap done at Sat Mar 17 01:10:51 2018; 1 IP address (1 host up) scanned in 1.26 seconds
	[+] 159.89.225.14
	[+]
	  Supported authentication methods:
	    publickey
	    password
	osail intrusive(ssh-auth-methods)> use safe/ssh2-enum-algos
	osail safe(ssh2-enum-algos)> use safe/set RHOST  159.89.225.14
	osail safe(ssh2-enum-algos)> run
	[*] /usr/bin/nmap -p 22 -A -oX - --script ssh2-enum-algos --script-args "" --host-timeout=10 --dns-servers=8.8.8.8 --max-retries=10 --max-scan-delay=0 --min-parallelism=1 --scan-delay=0 --max-parallelism=100 159.89.225.14
	[+] Nmap done at Sat Mar 17 01:11:06 2018; 1 IP address (1 host up) scanned in 1.08 seconds
	[+] 159.89.225.14
	[+]
	  kex_algorithms: (6)
	      curve25519-sha256@libssh.org
	      ecdh-sha2-nistp256
	      ecdh-sha2-nistp384
	      ecdh-sha2-nistp521
	      diffie-hellman-group-exchange-sha256
	      diffie-hellman-group14-sha1
	  server_host_key_algorithms: (5)
	      ssh-rsa
	      rsa-sha2-512
	      rsa-sha2-256
	      ecdsa-sha2-nistp256
	      ssh-ed25519
	  encryption_algorithms: (6)
	      chacha20-poly1305@openssh.com
	      aes128-ctr
	      aes192-ctr
	      aes256-ctr
	      aes128-gcm@openssh.com
	      aes256-gcm@openssh.com
	  mac_algorithms: (10)
	      umac-64-etm@openssh.com
	      umac-128-etm@openssh.com
	      hmac-sha2-256-etm@openssh.com
	      hmac-sha2-512-etm@openssh.com
	      hmac-sha1-etm@openssh.com
	      umac-64@openssh.com
	      umac-128@openssh.com
	      hmac-sha2-256
	      hmac-sha2-512
	      hmac-sha1
	  compression_algorithms: (2)
	      none
	      zlib@openssh.com
	osail safe(ssh2-enum-algos)> hosts 159.89.225.14
	    Host                 Hostname
	    ----                 --------
	    159.89.225.14
	    Port 25/tcp (smtp): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 21/tcp (unknown): 	State: open
	        CPE
	           cpe:/a:vsftpd:vsftpd:3.0.3
	        Analysis
	           ftp-syst
	               STAT=
	FTP server status:
	     Connected to ::ffff:x.x.x.x
	     Logged in as ftp
	     TYPE: ASCII
	     No session bandwidth limit
	     Session timeout in seconds is 300
	     Control connection is plain text
	     Data connections will be plain text
	     At session startup, client count was 16
	     vsFTPd 3.0.3 - secure, fast, stable
	End of status
	    Port 22/tcp (unknown): 	State: open
	        CPE
	           cpe:/a:openbsd:openssh:7.2p2
	        Analysis
	           ssh-auth-methods
	               publickey
	               password
	               publickey
	               password
	           ssh-hostkey
	               a9c8cad7975047aafaed51462eafbaf9
	               ecdsa-sha2-nistp256
	               329c3f17956c3f6e3ceec6f79bd80056
	               ssh-ed25519
	               43ff5a8c3a065c8a371a7c696bd5a240
	               AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCVPtJldY/DLYM/YF33JwtJxAexVvfngTPQ7AC/yhJe89sbilgT1QbjdMTiUiaZzdsOGcUIEmi0Er/Weqewhk7E=
	               256
	               AAAAB3NzaC1yc2EAAAADAQABAAABAQC8XmX6NUku0CcKR6F5tfOnKRkw1ndqmjLRMniykYj4vVjLnpUlxokTdUCi/KR09H1z8kNk3869xW7nu9fN0vhMuOhmCBjKBTWiWzMd7s6JWrzH0ArKQsT9+UpOrf74n3LoxtgmuXmjW8Am/FW7spsFb/b8e/s1s/Gtzs0aVQ+KuRr6Qr9dz3j6c/dLZLP3sKKBFjiIOHjPputPO/17x8Hhs92fhHc5LNtoGKd4Te7duCt+HlJ7mXgq4uPRuboguY3dtfDVdBUoOsOjkXLObyWjk8e534sKhpP8AWgw6txiTHr+DvBMyeU8BtzMjdsWAT7G6yyq84uQCb5TIAhY2/z3
	               2048.0
	               AAAAC3NzaC1lZDI1NTE5AAAAINCNGhPoag3xFg0X2gsxDkQy/xkye2fZ7yHVYYXpqQ3y
	               ssh-rsa
	               a9c8cad7975047aafaed51462eafbaf9
	               ecdsa-sha2-nistp256
	               329c3f17956c3f6e3ceec6f79bd80056
	               ssh-ed25519
	               43ff5a8c3a065c8a371a7c696bd5a240
	               AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCVPtJldY/DLYM/YF33JwtJxAexVvfngTPQ7AC/yhJe89sbilgT1QbjdMTiUiaZzdsOGcUIEmi0Er/Weqewhk7E=
	               256
	               AAAAB3NzaC1yc2EAAAADAQABAAABAQC8XmX6NUku0CcKR6F5tfOnKRkw1ndqmjLRMniykYj4vVjLnpUlxokTdUCi/KR09H1z8kNk3869xW7nu9fN0vhMuOhmCBjKBTWiWzMd7s6JWrzH0ArKQsT9+UpOrf74n3LoxtgmuXmjW8Am/FW7spsFb/b8e/s1s/Gtzs0aVQ+KuRr6Qr9dz3j6c/dLZLP3sKKBFjiIOHjPputPO/17x8Hhs92fhHc5LNtoGKd4Te7duCt+HlJ7mXgq4uPRuboguY3dtfDVdBUoOsOjkXLObyWjk8e534sKhpP8AWgw6txiTHr+DvBMyeU8BtzMjdsWAT7G6yyq84uQCb5TIAhY2/z3
	               2048.0
	               AAAAC3NzaC1lZDI1NTE5AAAAINCNGhPoag3xFg0X2gsxDkQy/xkye2fZ7yHVYYXpqQ3y
	               ssh-rsa
	           ssh2-enum-algos
	               ssh-rsa
	               hmac-sha2-512-etm@openssh.com
	               umac-128@openssh.com
	               zlib@openssh.com
	               curve25519-sha256@libssh.org
	               aes256-ctr
	               hmac-sha1
	               aes256-gcm@openssh.com
	               hmac-sha2-256
	               umac-128-etm@openssh.com
	               diffie-hellman-group14-sha1
	               rsa-sha2-256
	               aes128-ctr
	               ecdh-sha2-nistp521
	               ecdh-sha2-nistp256
	               aes192-ctr
	               diffie-hellman-group-exchange-sha256
	               hmac-sha2-512
	               hmac-sha1-etm@openssh.com
	               umac-64-etm@openssh.com
	               hmac-sha2-256-etm@openssh.com
	               ssh-ed25519
	               chacha20-poly1305@openssh.com
	               none
	               rsa-sha2-512
	               umac-64@openssh.com
	               ecdsa-sha2-nistp256
	               aes128-gcm@openssh.com
	               ecdh-sha2-nistp384
	               ssh-rsa
	               hmac-sha2-512-etm@openssh.com
	               umac-128@openssh.com
	               zlib@openssh.com
	               curve25519-sha256@libssh.org
	               aes256-ctr
	               hmac-sha1
	               aes256-gcm@openssh.com
	               hmac-sha2-256
	               umac-128-etm@openssh.com
	               diffie-hellman-group14-sha1
	               rsa-sha2-256
	               aes128-ctr
	               ecdh-sha2-nistp521
	               ecdh-sha2-nistp256
	               aes192-ctr
	               diffie-hellman-group-exchange-sha256
	               hmac-sha2-512
	               hmac-sha1-etm@openssh.com
	               umac-64-etm@openssh.com
	               hmac-sha2-256-etm@openssh.com
	               ssh-ed25519
	               chacha20-poly1305@openssh.com
	               none
	               rsa-sha2-512
	               umac-64@openssh.com
	               ecdsa-sha2-nistp256
	               aes128-gcm@openssh.com
	               ecdh-sha2-nistp384
	    Port 554/tcp (tcpwrapped): 	State: open
	        CPE
	           None
	        Analysis
	    Port 7070/tcp (tcpwrapped): 	State: open
	        CPE
	           None
	        Analysis
	    Port 445/tcp (microsoft-ds): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 135/tcp (msrpc): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 139/tcp (netbios-ssn): 	State: filtered
	        CPE
	           None
	        Analysis
	osail safe(ssh2-enum-algos)> search resol
	broadcast/broadcast-wpad-discover      Retrieves a list of proxy servers on a LAN using the Web Pr
	broadcast/llmnr-resolve                Resolves a hostname by using the LLMNR (Link-Local Multicas
	discovery/dns/cache-snoop              Performs DNS cache snooping against a DNS server.  There ar
	discovery/dns/ip6-arpa-scan            Performs a quick reverse DNS lookup of an IPv6 network usin
	discovery/hostmap/bfk                  Discovers hostnames that resolve to the target's IP address
	discovery/hostmap/ip2hosts             Finds hostnames that resolve to the target's IP address by
	discovery/llmnr-resolve                Resolves a hostname by using the LLMNR (Link-Local Multicas
	discovery/resolveall                   Resolves hostnames and adds every address (IPv4 or IPv6, de
	external/hostmap/bfk                   Discovers hostnames that resolve to the target's IP address
	external/hostmap/ip2hosts              Finds hostnames that resolve to the target's IP address by
	intrusive/dns/cache-snoop              Performs DNS cache snooping against a DNS server.  There ar
	intrusive/dns/ip6-arpa-scan            Performs a quick reverse DNS lookup of an IPv6 network usin
	safe/broadcast-wpad-discover           Retrieves a list of proxy servers on a LAN using the Web Pr
	safe/hostmap/robtex                    Discovers hostnames that resolve to the target's IP address
	safe/llmnr-resolve                     Resolves a hostname by using the LLMNR (Link-Local Multicas
	safe/resolveall                        Resolves hostnames and adds every address (IPv4 or IPv6, de
	osail safe(ssh2-enum-algos)> use safe/hostmap/robtex
	osail safe(hostmap-robtex)> use safe/set RHOST  159.89.225.14
	osail safe(hostmap-robtex)> run
	[*] /usr/bin/nmap -p 80 -A -oX - --script hostmap-robtex --script-args "" --host-timeout=10 --dns-servers=8.8.8.8 --max-retries=10 --max-scan-delay=0 --min-parallelism=1 --scan-delay=0 --max-parallelism=100 159.89.225.14
	[+] Nmap done at Sat Mar 17 01:12:03 2018; 1 IP address (1 host up) scanned in 1.45 seconds
	[+] 159.89.225.14
	[+] ERROR: Script execution failed (use -d to debug)
	osail safe(hostmap-robtex)> use discovery/resolveall
	osail safe(resolveall)> set RHOST  159.89.225.14
	osail safe(resolveall)> run
	[*] /usr/bin/nmap -p 80 -A -oX - --script resolveall --script-args "" --host-timeout=10 --dns-servers=8.8.8.8 --max-retries=10 --max-scan-delay=0 --min-parallelism=1 --scan-delay=0 --max-parallelism=100 159.89.225.14
	[+] Nmap done at Sat Mar 17 01:12:18 2018; 1 IP address (1 host up) scanned in 0.86 seconds
	[+] 159.89.225.14
	osail safe(resolveall)> hosts 159.89.225.14
	    Host                 Hostname
	    ----                 --------
	    159.89.225.14
	    Port 25/tcp (smtp): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 21/tcp (unknown): 	State: open
	        CPE
	           cpe:/a:vsftpd:vsftpd:3.0.3
	        Analysis
	           ftp-syst
	               STAT=
	FTP server status:
	     Connected to ::ffff:x.x.x.x
	     Logged in as ftp
	     TYPE: ASCII
	     No session bandwidth limit
	     Session timeout in seconds is 300
	     Control connection is plain text
	     Data connections will be plain text
	     At session startup, client count was 16
	     vsFTPd 3.0.3 - secure, fast, stable
	End of status
	    Port 22/tcp (unknown): 	State: open
	        CPE
	           cpe:/a:openbsd:openssh:7.2p2
	        Analysis
	           ssh-auth-methods
	               publickey
	               password
	               publickey
	               password
	           ssh-hostkey
	               a9c8cad7975047aafaed51462eafbaf9
	               ecdsa-sha2-nistp256
	               329c3f17956c3f6e3ceec6f79bd80056
	               ssh-ed25519
	               43ff5a8c3a065c8a371a7c696bd5a240
	               AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCVPtJldY/DLYM/YF33JwtJxAexVvfngTPQ7AC/yhJe89sbilgT1QbjdMTiUiaZzdsOGcUIEmi0Er/Weqewhk7E=
	               256
	               AAAAB3NzaC1yc2EAAAADAQABAAABAQC8XmX6NUku0CcKR6F5tfOnKRkw1ndqmjLRMniykYj4vVjLnpUlxokTdUCi/KR09H1z8kNk3869xW7nu9fN0vhMuOhmCBjKBTWiWzMd7s6JWrzH0ArKQsT9+UpOrf74n3LoxtgmuXmjW8Am/FW7spsFb/b8e/s1s/Gtzs0aVQ+KuRr6Qr9dz3j6c/dLZLP3sKKBFjiIOHjPputPO/17x8Hhs92fhHc5LNtoGKd4Te7duCt+HlJ7mXgq4uPRuboguY3dtfDVdBUoOsOjkXLObyWjk8e534sKhpP8AWgw6txiTHr+DvBMyeU8BtzMjdsWAT7G6yyq84uQCb5TIAhY2/z3
	               2048.0
	               AAAAC3NzaC1lZDI1NTE5AAAAINCNGhPoag3xFg0X2gsxDkQy/xkye2fZ7yHVYYXpqQ3y
	               ssh-rsa
	               a9c8cad7975047aafaed51462eafbaf9
	               ecdsa-sha2-nistp256
	               329c3f17956c3f6e3ceec6f79bd80056
	               ssh-ed25519
	               43ff5a8c3a065c8a371a7c696bd5a240
	               AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCVPtJldY/DLYM/YF33JwtJxAexVvfngTPQ7AC/yhJe89sbilgT1QbjdMTiUiaZzdsOGcUIEmi0Er/Weqewhk7E=
	               256
	               AAAAB3NzaC1yc2EAAAADAQABAAABAQC8XmX6NUku0CcKR6F5tfOnKRkw1ndqmjLRMniykYj4vVjLnpUlxokTdUCi/KR09H1z8kNk3869xW7nu9fN0vhMuOhmCBjKBTWiWzMd7s6JWrzH0ArKQsT9+UpOrf74n3LoxtgmuXmjW8Am/FW7spsFb/b8e/s1s/Gtzs0aVQ+KuRr6Qr9dz3j6c/dLZLP3sKKBFjiIOHjPputPO/17x8Hhs92fhHc5LNtoGKd4Te7duCt+HlJ7mXgq4uPRuboguY3dtfDVdBUoOsOjkXLObyWjk8e534sKhpP8AWgw6txiTHr+DvBMyeU8BtzMjdsWAT7G6yyq84uQCb5TIAhY2/z3
	               2048.0
	               AAAAC3NzaC1lZDI1NTE5AAAAINCNGhPoag3xFg0X2gsxDkQy/xkye2fZ7yHVYYXpqQ3y
	               ssh-rsa
	           ssh2-enum-algos
	               ssh-rsa
	               hmac-sha2-512-etm@openssh.com
	               umac-128@openssh.com
	               zlib@openssh.com
	               curve25519-sha256@libssh.org
	               aes256-ctr
	               hmac-sha1
	               aes256-gcm@openssh.com
	               hmac-sha2-256
	               umac-128-etm@openssh.com
	               diffie-hellman-group14-sha1
	               rsa-sha2-256
	               aes128-ctr
	               ecdh-sha2-nistp521
	               ecdh-sha2-nistp256
	               aes192-ctr
	               diffie-hellman-group-exchange-sha256
	               hmac-sha2-512
	               hmac-sha1-etm@openssh.com
	               umac-64-etm@openssh.com
	               hmac-sha2-256-etm@openssh.com
	               ssh-ed25519
	               chacha20-poly1305@openssh.com
	               none
	               rsa-sha2-512
	               umac-64@openssh.com
	               ecdsa-sha2-nistp256
	               aes128-gcm@openssh.com
	               ecdh-sha2-nistp384
	               ssh-rsa
	               hmac-sha2-512-etm@openssh.com
	               umac-128@openssh.com
	               zlib@openssh.com
	               curve25519-sha256@libssh.org
	               aes256-ctr
	               hmac-sha1
	               aes256-gcm@openssh.com
	               hmac-sha2-256
	               umac-128-etm@openssh.com
	               diffie-hellman-group14-sha1
	               rsa-sha2-256
	               aes128-ctr
	               ecdh-sha2-nistp521
	               ecdh-sha2-nistp256
	               aes192-ctr
	               diffie-hellman-group-exchange-sha256
	               hmac-sha2-512
	               hmac-sha1-etm@openssh.com
	               umac-64-etm@openssh.com
	               hmac-sha2-256-etm@openssh.com
	               ssh-ed25519
	               chacha20-poly1305@openssh.com
	               none
	               rsa-sha2-512
	               umac-64@openssh.com
	               ecdsa-sha2-nistp256
	               aes128-gcm@openssh.com
	               ecdh-sha2-nistp384
	    Port 554/tcp (tcpwrapped): 	State: open
	        CPE
	           None
	        Analysis
	    Port 7070/tcp (tcpwrapped): 	State: open
	        CPE
	           None
	        Analysis
	    Port 445/tcp (microsoft-ds): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 135/tcp (msrpc): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 139/tcp (netbios-ssn): 	State: filtered
	        CPE
	           None
	        Analysis
	    Port 80/tcp (http): 	State: closed
	        CPE
	           None
	        Analysis
	osail safe(resolveall)>
