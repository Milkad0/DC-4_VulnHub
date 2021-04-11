# DC-4 VulnHub
## Configuration

### Step 1 : Download

- For this pentest audit we are going to use this instance :

    https://www.vulnhub.com/entry/dc-4,313/


### Step 2 : Virtualization product

- Unzip the file

- Use VMWare or VirtualBox to add the VM

### Step 3 : Virtual configuration

- Put the machine under the same subnet as your attack machine

### Step 4 : Start

- Start both VM

### Advise

Never expose the vulnerable machine on internet, always in local

I recommand to use a Kali VM to process the attack, you can found some preconfigured VM here :

[Kali offensive security](https://www.offensive-security.com/kali-linux-vm-vmware-virtualbox-image-download/#1572305786534-030ce714-cc3b)

## Let's hack


The 2 VMs are mounted in NAT and are therefore on the same network. We will be able to analyze it with nmap to find out which address the DC4 machine has retrieved and to know a little more in details.
List of network ip addresses with: nmap -sP 10.0.2.0/24
We notice an ip address in .5 which did not exist when the machine was down. We will therefore use the –A option to have more information on it: nmap -A 10.0.2.5

![image](https://user-images.githubusercontent.com/44178372/114249372-b411a280-999a-11eb-97e7-298c00cce2d1.png)


![image](https://user-images.githubusercontent.com/44178372/114249383-becc3780-999a-11eb-92b1-e1ca1ed06203.png)

The header is "Admin information systems login", let's test some basic logins / mdps like admin / admin, admin / admin123 but no luck. We will therefore bruteforcer with hydra and the command: hydra -l admin -P /usr/share/wordlists/dirb/big.txt 10.0.2.5 http-post-form "/login.php:username=^USER^&password=^ PASS ^ & submit = Submit: S = logout "-V
In the end we have as login: admin and as mdp: happy

![image](https://user-images.githubusercontent.com/44178372/114249396-c7bd0900-999a-11eb-8eb1-db08f55122e9.png)

We access an interface where commands are carried out with the result:

![image](https://user-images.githubusercontent.com/44178372/114249402-cb509000-999a-11eb-9b2b-193a9646961f.png)

We will inspect the element and take advantage of being able to execute commands to display the passwd or shadow folders. Having no result for shadow, we have a result for passwd:

![image](https://user-images.githubusercontent.com/44178372/114249431-defbf680-999a-11eb-9bee-3d780b16675c.png)

We notice the existence of several users like charles, jim or sam. By browsing in their / home, we find an old password directory with Jim. We therefore retrieved the list of all users and all old mdp found at Jim's to try to bully one of the accounts (mainly charles, jim or sam). To do this, we will always use hydra and use the ssh protocol: hydra -l jim -P /usr/share/wordlists/dirb/projectmdp.txt 10.0.2.5 ssh –V. Bingo, we find the mdp

![image](https://user-images.githubusercontent.com/44178372/114249442-e7ecc800-999a-11eb-8ab3-7bd3ab3c942b.png)

We can connect in ssh with the jim account, we notice that there are several files and that we have access to his mailbox. The mails are usually found in the / var / mail folder. We notice that Charles sent him an email with his password in clear.

![image](https://user-images.githubusercontent.com/44178372/114249451-f0450300-999a-11eb-8942-71e0478d7825.png)

By the way, trying to get root with jim, we get rejected directly telling us that he has no root rights.

![image](https://user-images.githubusercontent.com/44178372/114249464-f804a780-999a-11eb-90be-3b3fbc83004e.png)

Whereas if you want to be root with Charles, the error message is different. As if they had sudo rights but not all of them.

![image](https://user-images.githubusercontent.com/44178372/114249479-0357d300-999b-11eb-913e-1203d47fe75c.png)

Later, we learned that thanks to sudo –l, we could see the commands that it could run as root.

![image](https://user-images.githubusercontent.com/44178372/114249486-08b51d80-999b-11eb-9b4d-9c1e5b784175.png)

With teehee –help, we learn that it copies the entry to a file. We can therefore add a new user in / etc / passwd since we had access. Obviously, we added a user with a UID & GID corresponding to root. Using the following command: echo "augustin :: 0: 0 ::: / bin / sh" | sudo teehee -a / etc / passwd
Verification by changing the user, we are finally root!

![image](https://user-images.githubusercontent.com/44178372/114249495-110d5880-999b-11eb-8389-7fdaaa8c3950.png)

Then retrieving the flag at the root of root:

![image](https://user-images.githubusercontent.com/44178372/114249507-1b2f5700-999b-11eb-9205-60b26ddc896f.png)

## Audit

### Threat n°1 : Broken authentication | Using the http protocol
#### Vulnerability risk
When logging in using an HTTP website, the hacker can see the username and password. In addition, when using an HTTP website, everything the server returns is also readable. A hacker can then transform the website easily. If a website uses HTTP instead of HTTPS, any information transmitted over the network can be seen and used against the person in question. When we log into an account on a website, we can see that the hacker sees the password when using HTTP while he cannot even see that we communicate the password when we use HTTPS because everything is encrypted. The http protocol is not at all secure against SQL injections, XSS, bad security configurations, faulty authentication, session management or against direct unsecured object references.
#### Operation
The site was in http, so we could modify commands that were called up without worry, but we will develop this part a little further. However, we did not perform an SQL injection or other attack to find vulnerabilities in this protocol due to lack of time.

From

![image](https://user-images.githubusercontent.com/44178372/114249574-4f0a7c80-999b-11eb-8525-2fd9ec31a917.png)

To

![image](https://user-images.githubusercontent.com/44178372/114249579-516cd680-999b-11eb-9fc3-515eaf01f213.png)


#### Correction recommendation
HTTP, HyperText Transfer Protocol, is used to communicate information between a client and a server. It is transmitted through the application layer on the OSI model. The OSI model is a standard that can be used for computers to communicate with each other. It is used to characterize protocols and better understand their interaction.
When using HTTPS, HyperText Transfer Protocol Secured, the data transmitted in the packet is encrypted. In addition to HTTP, there is a protocol that secures the data transmitted: TLS, Transport Layer Secure.

### Threat n°2 : Broken authentication | Unsecured login / password
#### Vulnerability risk
One of the weak points of any data security system, no matter how strong, is the legitimate, password-protected access point for authorized users. If a hacker can get your username and password, then they can log into your system and gain access to all the information and system controls that would normally be available to you. This could result in considerable financial harm to your business or organization.
Despite this, many people tend to make very simple mistakes that make their passwords more vulnerable to attack.
In addition, the login "admin" for an "admin" is a little too common as a login, then you just have to find the password.

#### Operation
We were able to recover the passwords of some users, including the admin password. Certainly thanks to BruteForce that we will discuss shortly after, but the passwords were much too weak, whether for jim or for admin.

#### Correction recommendation
According to ANSSI, you must choose passwords of at least 12 characters of different types (upper case, lower case, numbers, special characters).
Two methods for choosing your passwords:
• The phonetic method: "I bought eight CDs for a hundred euros this afternoon" will become ght8CD% E7am;
• The first letter method: the quote "one yours is better than two you will have" will give 1tvmQ2tl’A.
Charles's password seemed a bit more secure:

![image](https://user-images.githubusercontent.com/44178372/114249633-75c8b300-999b-11eb-8a0c-268d86a840f6.png)


### Threat n°3 : Broken authentication | BruteForce Attack
#### Vulnerability risk
A brute force attack is one of the simplest and least sophisticated hacking methods. The theory behind such an attack is that if you make an infinite number of attempts to guess a password, you are bound to be right in the end.
The attacker aims to forcibly access a user account by trying to guess the username / email and password. Usually the motive is to use the hacked account to execute a large scale attack, steal sensitive data, shut down the system, or a combination of the three.
It doesn't take a lot of imagination or knowledge to create code that performs this type of attack, and there are even widely available automated tools that submit several thousand password attempts per second like the Hydra tool we have. used.

#### Operation
We used Hydra, present on Kali, is an online password cracker software, Hydra. This software is able to crack passwords on a large number of different protocols or databases: HTTP, HTTPS, SSH, FTP, MYSQL etc.
We directly have wordlists that we can use and that we used on the "admin" user. After a few seconds, hundreds of passwords are already tested with the login "admin" and we find the password "happy"

![image](https://user-images.githubusercontent.com/44178372/114249661-86792900-999b-11eb-8709-beb24e8fe74d.png)


#### Correction recommendation
There are many ways to stop or prevent brute force attacks. The most obvious is a strong password policy. Every web application or public server must enforce the use of strong passwords as we have seen before.
There are other ways to prevent a brute force attack such as:

- Limit unsuccessful login attempts
- Make the root user inaccessible via SSH by modifying the sshd_config file
- Do not use a default port, change the port line in your sshd_configfile file
- Use the Captcha
- Limit connections to a specific IP address or range of IP addresses
- Two-factor authentication
- Unique login URLs
- Monitor server logs


### Threat n°4 : Security misconfiguration | Display of versions
#### Vulnerability risk
When opening a website, some server programs transfer additional information, such as server version, operating system or plug-ins used.
The attackers could use this information to exploit in a targeted way the weak points of the software used. This makes it more difficult for attackers to conceal this sensitive information.

#### Operation
We can see by doing a scan using nmap that the server versions are not hidden, this allows us to investigate possible vulnerabilities in those versions.
We will see later the vulnerabilities linked to the different versions found.

![image](https://user-images.githubusercontent.com/44178372/114249747-bf190280-999b-11eb-991f-f2ab21645649.png)

#### Correction recommendation
You just have to hide the version by properly configuring your server so that it does not make the version public.

### Threat n°5 : Security misconfiguration | Vuln OpenSSH 7.4 or Nginx
#### Vulnerability risk
Information disclosure is extensive and modification of some files (CVE-2018-15919) or system information is possible, but the attacker has no control over what can be changed, or the scope of what. attacker can affect is limited (CVE-2017-15906)

#### Operation
We did not exploit the flaw related to the CVE CVE-2018-15919 but the remotely observable behavior in auth-gss2.c in OpenSSH through 7.8 could be used by remote attackers to detect the existence of users. on a target system when GSS2 is used.
We did not exploit the flaw related to the CVE CVE-2017-15906 but the process_open function of sftp-server.c in OpenSSH before 7.6 does not correctly prevent write operations in read-only mode, which allows attackers to create zero length files.

#### Correction recommendation
For this type of flaw, firstly it would be good not to publicly display the version of the servers and then to regularly update the software and various tools is necessary.
For example to hide the version of Nginx, just add the following line in the configuration: "server_tokens off; "

### Threat n°6 : Security misconfiguration | Vuln Kernel 4.9.0
#### Vulnerability risk
There are many CVEs related to the Linux 4.9.0 kernel, we will take the most critical. CVE-2019-15292 where there is full disclosure of information resulting in disclosure of all files in the system. There is also a total compromise of the integrity of the system. There is a total loss of system protection, which has the consequence of compromising the entire system and finally there may be a total shutdown of the affected resource. The attacker can make the resource completely unavailable.

#### Operation
We did not exploit the CVE-related vulnerability CVE-2019-15292, but an issue was discovered in the Linux kernel prior to version 5.0.9. There is a use-after-free in atalk_proc_exit, related to net / appletalk / atalk_proc.c, net / appletalk / ddp.c, and net / appletalk / sysctl_net_atalk.c.

#### Correction recommendation
Update the OS regularly and not start working with an older version of an OS.

### Threat n°7 : Broken access control | Vuln Rights on folders / files
#### Vulnerability risk
Most users grant themselves full read, write, and execute rights for their home directory and no rights for the group or other people, but some people, for various reasons, might have a slightly different setup. .
Normally, for the best security, you should not give the group or others write access to your home directory, but running without read can sometimes be useful. This allows people to access your personal directory but does not allow them to see what is in it.
There are also files with information about user passwords and their name. Even having only read rights to it can be very useful for an attacker to gain access to the root account or to a user with root or other rights.

#### Operation
We were able to exploit this flaw by having read permission on the old-password.bak file:

![image](https://user-images.githubusercontent.com/44178372/114249829-ff788080-999b-11eb-85c9-c14feaa07a58.png)

#### Correction recommendation
Authorization control in Linux is simple and allows you to have good control of the system. However, this simplicity does not always cover all needs. Each file is owned by a unique user and group, which can be problematic and restrictive.
To allow more precise management of access permissions, there are ACLs (Access Control List) that grant privileges to several users or several groups for the same file.
However, it is essential that critical files are accessible, read, write, or execute, to those who really need them.

### Threat n°8 : Sensitive data exposure | Transmission of important information in clear
#### Vulnerability risk
Being able to access the network, the system, certain applications or other vulnerabilities that would allow the attacker to penetrate even more.

#### Operation
In Jim's emails, we have Charles sending Jim an unencrypted email with his password inside.

![image](https://user-images.githubusercontent.com/44178372/114249860-1ae38b80-999c-11eb-81a3-1ff3b19ab690.png)

#### Correction recommendation
There are different solutions for transmitting important information such as passwords:
• Communicate passwords verbally, directly to the person
• Communicate passwords through a channel other than the corporate internet network such as using SMS or secure instant messaging
• Communicate passwords via encrypted email
• Transfer passwords via a safe such as KeePass

### Threat n°9 : Broken access control | Root rights of certain users for certain commands
#### Vulnerability risk
The SUDO (Substitute User and Do) command allows users to delegate privilege resources: users can run specific commands under other users (also root) using their own passwords instead of the user's. or without a password depending on the settings in the / etc / sudoers file. They can thus, thanks to certain flaws in certain tools, increase privileges and thus become root.

#### Operation
In order to exploit sudo users, we found out which commands the current user is allowed, using the sudo -l command:

![image](https://user-images.githubusercontent.com/44178372/114249886-3058b580-999c-11eb-82f9-b3f3e34880f3.png)

He can therefore use the teehee command in root mode which will add content to a file. He can therefore add whatever he wants in the passwd file, for example, and thus create a user with root rights.

#### Correction recommendation
Escalation of privileges by improperly configured SUID executables is negligible. Therefore, administrators should evaluate all SUID binaries and determine if they should work with elevated user permissions. Particular attention should be paid to applications with the ability to execute code or write arbitrary data to the system.

### Threat n°10 : Injection | OS command injection
#### Vulnerability risk
Command injection is an attack aimed at executing arbitrary commands on the host operating system through a vulnerable application. Command injection attacks are possible when an application passes dangerous user-supplied data to a system shell. In this attack, the operating system commands provided by the attacker are usually executed with the privileges of the vulnerable application.

Command injection attacks are possible in large part due to insufficient input validation.
This attack differs from code injection, in that code injection allows the attacker to add their own code which is then executed by the application. In command injection, the attacker extends the default functionality of the application, which executes system commands, without needing to inject code.

#### Operation
We were able to use this method by modifying an http request asking to perform a system command that can display the different users of the system:

From

![image](https://user-images.githubusercontent.com/44178372/114249924-567e5580-999c-11eb-9714-5bac871b1a45.png)

To

![image](https://user-images.githubusercontent.com/44178372/114249927-59794600-999c-11eb-8f43-b9b819a65f1a.png)

#### Correction recommendation

By far the most effective way to prevent operating system command injection vulnerabilities is to never invoke operating system commands from application layer code.
If it is considered unavoidable to invoke operating system commands with user-supplied input, then rigorous input validation should be performed. Here are some examples of effective validation:
- Validation against a white list of authorized values
- Validate that the entry is a number
- Validate that the entry contains only alphanumeric characters, no other syntax or no spaces
