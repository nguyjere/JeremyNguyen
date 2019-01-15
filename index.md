### Welcome to my CS 373 Defense Against the Dark Arts Page!

Each week I will submit a post about my reflections on what I learned from the weekly lectures or labs of CS373. This includes ideas, concepts, tools, or whatever conclusions I came to.

# Week 2
This week is about forensice investigation, which is able extracting data and determining what happened to a system.

*Forensics in a Nutshell:*
1. Evidence Acquisition
2. Investigation and Analysis
3. Reporting Results

*Four Principles you must always adhere to:*
1. Minimalize Data Loss
2. Record Everything
3. Analyze all data collected (evidence)
4. Report Findings

**What is evidence?**

Evidence is anything you can use prove, or disprove, a fact in court. Some examples of evidences are...
* Network (firewalls, IDS, routers...)
* Operating System
* Database and applications
* peripherals
* removable media (CD/DVD, USB)
* human testimony

**Triage - Multiple ways of proving a conclusion**

**Evidence Handling**

Preservation of the integrity of the evidence at all times by...
* Creating a cryptographic hash of the entire disl
* Create bit-images copies and analyze them
* Create a cryptographic hash of the copy and ensure it matches the original
* Lock the original disk in a limited-access room/container

**Investigation Cycle**

* Verification
* System Description
* Evidence Acquistion
* Loop:
  * Timeline Analysis
  * Media Analysis
  * String or byte Search
  * Data Recovery
  * Report Analysis

**Locard's Exchange Principle**

When two objects come in contact with each other, there is always a transference of material between the objects.
Once contaminated, stay contaminated!

**Order of Volatility**

When collecting evidence, you should always start from the volatile to the less volatile (refer to RFC 3227)
Example:
1. System Memory
2. Temporary File Sytems (swap file / paging file)
3. Process Tables & Network Connections
4. Network Routing Information & ARP Cache
5. Forensice Acquisition of Disks
6. Remote Logging & Monitoring Data
7. Physical Configuration & Network Topology
8. Backups

**FTK Imager Lab**

This tool is used to capture a memory dump. This tool should always be run from a CD-ROM, or USB stick, and never save the memory dump to the suspect's machine. Save with serial number, and data. You can use a commercial tool called FastDump with has CLI.

Also, this tool can copy the image of the disk which you can mount into a VM. In 'select image type' use 'RAW'. This tool can also copy protected file.

**Volatility**

A forensic tools for Windows and OSX that allows the users to analyze informations inside the memory dump such as hidden processes, orphanes threads, and hidden and injected code.

To use: $ volatility.exe -f <memory name> [--profile=<profile name>] <plugin>
 
 imageinfo : Displays the suggested profile of the memory dump, date you took the memory dump, and more.
 psscan : Displays the list of processes that was running on the system.
 dlllist -p <pid> : Displays the list of dlls used by a process id
 netscan : Displays a list of network connections made by which processes.
 Deskscan : Displays the list of processes that was running on the desktop
 Getsids : 

**Timeline Creation and Analysis**
MAC Time : Modified, Access, Creation time
$MFT (master file table) : database in which information about every file and directory on an NT File System (NTFS) volume is stored.
Tools: Volatility, Reg-Ripper

 1. $ volatility.exe -f <memory name> imageinfo //to get the profile name
 2. $ volatility.exe -f --profile=<profile> timerliner --output=body >> timeliner.txt
 3. $ volatility.exe -f --profile=<profile> mftparser --output=body >> mftparser.txt

**Data Recovery**

Tool: Photorec -  Used to recovery files that are 'deleted' but the data still remains in the disk

1. Install OSFMount
2. Unzip carving_lab.zip to obtain 11-carve-fat.dd
3. OSFMount: Mount 11-carve-fat.dd to a drive such as E:/
4. Launch photorec_win.exe and select drive E:
5. Go to 'Options' > Select 'Unknown' > Select 'Other'
6. Select the destination folder to export the carved file to, then press 'c' to carve

# Week 1

This week is the introduction to the basics of malware. I learned the history of malwares, types of malwares, why they exist, and what their purposes are. Additionally, I got exposed to a couple tools that are used to analyze malwares in a sandboxed environment.

**Why Malware Exist**

The word malware comes from the combination of the word **mal**icious and soft**ware**. So they intents are malicious and they are create by people who are motivated by destruction, spying, political gains, or financial gains. The creators of malware can be anybody. They can written by the government, activists, researchers/experimentalist, or a nobody in a basement. 

**Types of Malware**

This week we learned some types of malwares, which are listed below.
* Viruses
  * Parasitic -  Relies on a host file
  * Polymorphic - Changes their signature, or code, constantly to remain undetected
  * Worm - Spreads copies of themselves throughout the network then relies oin remote services for code execution
* Trojans - gives the creator backdoor access to the victim, or acts as a password stealer or keylogger. Disguised as a harmless software, or something entirely different
* Potentially Unwanted Program (PIP, PUA, PUS) - Undesired softwares that are installed without users permissions such as Adware, Spyware, and tools.

**Some Definitions**

* White (Clean) - Files that are clean, or okay. Nothing wrong
* Black (Dirty) - Files, or samples, that are infected.
* Gray - Uncertain if the sample or files are dirty or clean
* Sample -  a piece, or copy, of a malware
* Goat - a sacrifical (isolated) system that you allow the malware to infect to observe that the malware does
* Replication - to recreate the malware for observation
* Hash (md5 / sha1 / sha256) - a value of a file based on a crypographic algorithm/calculation to obscure the data for anyone except the owner of the hash key.

**Malware Naming Convention**

Each company has different naming convention but that all contain 5 elements: Type, Platform, Family, Variant, and Information.

ex. Trojan:Win32/Reveton.T!lnk -> Type:Platform/Family.Variant!Information

**Advanced Persistent Threats**

Aka APT, decribes three aspects of attacks that represents their profile, intent, and structure;
* Advanced - fluent with cyber intrusion methods and administrative techniques, and is capable of crafting custom exploits and replated tools
* Persistent - has a objective, or longer-term campaigns, and works toa chieve their goals without detection
* Thread -  organized, receives instructions, is sufficiently, funded to perform their (sometimes extended) operations, and is motivated.

APT-KILL-CHAIN
1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command and Control
7. Actions on Objectives

**Lab 1 Experience**

 In this lab we used various tools to observe the behaviors of a malware. These tools are ProcessExplorer, ProcMon, Fakenet, Flypaper, and Antispy
 
 * ProcessExplorer -  Allows you to see what process is running, what resources its using, and what other process it spawned. Also allows you suspend, or kill, process. Useful to see if its executing command-lines, TCP/IP actions, or where it autostarted.
 * ProcMon -  Process Monitor shows you when and where the program modifies files, registeries, and make TCP/IP request in real-time
 * Fakenet - Tricks the system into thinking it is connected to the internet and also shows the host name of the UDP or TCP/IP request.
 * Flypaper - Simply blocks traffic to/from TCP/IP and UDP, and also prevents programs for exiting
 * Antispy - Shows when process started, what process are autostarted by schedule tasks, and the network activities.
 
 Using these tools, to observe a malware in Week1\Class1\Lab2\Replication\Samle1\evil.exe, I was able to describe its behaviors. Upon clicking, it doesn't seem to do anything but it is running stuff in the background. Primarily, it created a list of schedule tasks to execute by running c:\ntldrs\funbots.bat then deletes itself. That schedule tasks is to execute c:\ntldrs\svchests.exe every 30 minutes to download or execute some files, probably tongji2.exe or pao[1].exe
 
 Using FakeNet, the malware wants to connect to www.hisunpharm.com, static.naver.net, and timeless888.com, which are also found in the string dump of evil.exe
 
 Knowning this, I think the easiest way to remove this malware is to deleted the c:\ntldrs folder, remove all the auto tasks in Task Scheduler, delete C:\Users\Admin\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\KLTT2YG3\pao[1].exe and  C:\Program Files\tongji2.exe. Then also revert the hosts file if possible, and change its permission back from 'everyone'.

