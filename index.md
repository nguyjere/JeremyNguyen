### Welcome to my CS 373 Defense Against the Dark Arts Page!

Each week I will submit a post about my reflections on what I learned from the weekly lectures or labs of CS373. This includes ideas, concepts, tools, or whatever conclusions I came to.

# Week 9-10

This week we learned about mobile platform and security, specifically they kind of malware that exist for mobile platforms.The three main mobile operating system (when the lecture was given) was Android, iOS, and Windows. Although, there was other players such as Firefox OS, Tizen, and Ubunto Touch.

**Android**

Android was created by a startup and was obtained by Google in 2007. The official primary langauge of Android is Java, and the app file format is .apl. When the app compiles, the executable file format is ELF (used to be .dex). The cost of registering you application to Google Play is $25, and the approval process is automated.

**iOS**

Apple has their own operating system for their iPhones, the iOS. The official language of iOS is Objective-C/C/C++, but I think now they include Swift. Their app file format is .ipa, but compiled into .app. They cost of registering your application cost $99/year for a developer license, and the application approval process is done manually.

**Windows**

Microsoft developed their operating system for Windows Phone, called Windows. It's official language is C# .NET or HTML5/JS. It's compressed application file format is .xap in Windows NT 7, or .appx in Windows NT 8. When compiled their application format is .dll.

**Sandboxing**

Generally, each application is sandboxed in their own environment to keep them isolated and prevent them from communication/interfering with other applications. Some except exist where two application will share the same environment if they are signed using the same digital signature. Below is the diagram by the presenter.

![Mobile App Sandbox](https://i.imgur.com/oNsP9QL.png)

**Jailbreaking and Rooting**

Jailbreaking is the act of cracking the iOS to allow users to perform root-like functions such as ssh, running un-authorized software, and unlocking carrier-locked iPhones. I used to do this in high school.

Rooting an Android is gaining root access to the operating system to gain more control and execute privileged operations. This allows user to remove bloatwares, or pre-installed applications, bypass restricitions from manufacturers/carriers, and download software with special features requiring root access.

**Symbian Worm Yxes**

Yxes was the first mobile botnet detected in 2009, and it was created to target Symbian OS 9 and above. It was spread through URL sent as SMS. This malware hide its footprint by disabling UI dialogs by executing silent outgoing Internet communications such as HTTP communications. It used HTTP communications to sent malware version, phone model, communicate with another Symbian package siliently installed, and exported contacts, files, and device informations to a remove server. It was able to kill system apps to avoid detection and encrypt URLs.

**IKEE**

IKEE was the first iOS malware found in November 2009. It affected jailbroken iPhones and prompts user to play $5 to remove the malware. This malware used the default SSH password "alpine" to infect users.

**FakePlayer & TapSnake**
FakePlayer and TapSnake were the first malware for Android found in August 2010. FakePlayer sends SMS messages to premium-rate numbers and executes payloads in the background without users consent. This application disguise itself as a media player application, and it was not in the Android Market. It typically affected Russian victims.

Tapsnak was similar, but it was found in the Android Market. It tracks and send GPS coordinates to a remote server, and runs in the background after boot.

**Geinimi**

Geinimi was the first Android Botnet found in December 2010. It was distributed in a third-party market in China as Google Play was banned in China. It leaked sensitive informations (GPS, IMEI, and installed apps) to a remove server, and downloaded additional APKs. It prompted users to uninstall an application and can execute commands sent by a remote C&C server.

**PJAPPS**

PJAPPS was another malware in 2011 that targeted Chinese users. This one was similar to Geinimi, but it also intercept incoming SMS.

**Google's reaction to Malware**

Google reacted to Android Security threats by removing malicious applications from the store, and banned malicious developers. Google was able to remotely remove malicious applications from users' phone, and download/install "Android Market Security Tool" in March 2011 to patch exploits.

Some malware authors took advantages of the fix by repackaging the Android Market Security Tool with malicious code, which sens SMS messages instructed by a C&C server. It also intercepted incoming SMS messeages and maining targeted Chinese telecom carriers.

**How Java is compiled in Android**

Applications written in Java is compiled into .dex file that contains all the class definitions, constants, and data defined in the Java source code. Nowadays, dex files are compressed into APK with resources and native codes. Upon installation, it gets decompressed, and dex file is converted to ELF file, that is executed in its own virtual environment within Android.

Within the APK package, you can view the .xml file (after uncompressed it) to view the permission the application specifies such as
"android.permission.WAKE_LOCK", or "android.permission.RECEIVE_BOOT_COMPLETED".

# Week 8

This week, we learned about one of the most common attack vectors in cyber security, emails. We learned how to identify phishing, and defense mechanism against phishing. Phishing is the act of sending emails to trick victims into clicking a malicious link, or entering sensitive informations into a link. Typically, these links are created to mock a legitimate email, or to convey a sense of urgency, or a call to action.

**Combating Spam Emails**

One of the methods to filter spam is using a reputation system for IP, messages, and URL. With IP, the email servers can filter IPs that are known to be spams (when many users mark the email as spam). Or measure the amount of email sent by one IP, a spike in email means its probably a spam. However, some attackers can use snowshoe attack to avoid being detected. Snowshoe attack is sending the same email but with different IP's. Attackers would alternate sending with a set of IP.

Another method to identify spam emails is by parsing the email contents using Regular Expression or by searching for common strings. If Regex captures a string in the email content that matches the rules of a spam email, then it will classify the email as spam. Regex can be used to search for sender's address, URLs, or strings such as "Wire $1000 by Tuesday to claim your reward".

Some useful Regex tools are Regex Coach or what I personally use, https://regexr.com/.

Spamhaus.org is a widely accepted authoritative source of reputation data in North America.

**CTE**

As a reference, here's an example of a rule used in a classification tree editor to classify emails.
```
Rules WITH rules as (
      SELECT heur_symbols as rule_id
      FROM message_data
      WHERE heur_symbols is not null
      limit 100000)
SELECT regexp_split_to_table(rules.rule_id, ','), count(*)
FROM rules
GROUP BY 1
ORDER BY 2 
DESCLIMIT 100
```

# Week 7

This week, we learn about web security and how hackers perform malicious actions through the web. Users can be attacked by several was: Phising, SEO Poisoning, Fake Anti-virus, Social Media Link Insertion, Forum Link Insertion, and Malvertising.

**Phishing**

Phising is when attackers sends a fake website that mirrors a legitimate website, tricking the user into entering their credentials or information into the fake website. The data will be send to the hacker to be used access banking/financial, email, or any other accounts. Phishing can be spotting by examining the URL and see if the URL does not match the URL of the legitimate website it is mocking. For example: www.wellsfargo.com vs www.we1lsfargo.com

**SEO Poisoning**

SEO Poisoning is short for Search Engine Optimization Poisioning, and it is a method for attackers to abuse the search engine's relevance agorithm. The attacker uses tools to determine the trending search, then create a website that contains the relevant contents of the trending topic to lure users into the websites that redirects them to a malicious content.

**Fake Anti-virus**

Fake AV is a website/pop-up that mimics an anti-virus alarming the users they may have malware installed, tricking the user to click a button (in a sense of urgency) that will lead them to either download a malware, or lead them to a payment site.

**Social Media Link Insertion**

Social Media Link Insertion is simply posting a URL to a malicious content on social media, tricking the users into clicking the link out of urgency, curiosity, or interest. Sometimes attackers can create a fake social media profile and build up fake information to make the profile appear legitimate. After gaining the users' trust, they post links to malicious contents where users' will submit or send their sensitive data.

**Malvertising**

Malvertising is using the advertising networks as a delivery mechanism for malware. There are 3 stages. The first stage is creating legitimate ads to gain some reputation and trust of the ad servers. The second stage is to offer malicious ads to distribute to as many website. The third stage is to deliver dynamic payloads to avoud AV detections to keep the malicious ad on the server as long as possible.

**Waterhole Attacks**

Waterhole attacks are targeted to app developers by hacking the resources known to be used by a community of developers. The attackers would inject an exploit into the selected sites visited by developers and the exploit would drop the malware into their vulnerable system. With the malware, the attack can perform their malicious activities against the developers.

**Defense**

There are many ways to defense against attackers from the web. The first way is using protections in browsers or network device to classify url and domain by reputations and filtering out domains with bad reputations. Also using extensions for search result link annotation would help user identify risking and safe websites. Using client and gateway anti-virus and anti-malware also adds another layer of protection against attackers by blocking malicious contents on the network level.

In the end, the best defense is educating the users. Training them to identify phishing, and being more cautious of submitting their data will prevent attacks from being successful.

# Week 6

Week 6 is about network security. In this lecture we learned about the multiple layers that makes up the defense against intrusions outside the network. The picture below shows a good diagram of the network zones.

![Network Zones](https://i.imgur.com/FakuYtA.png)

One important definitely is white-list policy, which is a set of policy that is permitted on the network. It is easier to define a finite set of policies then to define a set of black-list policy that can be infinite.

Firewalls are significant devices used in network security. Firewall are devices that sit between zones and filter traffic based on the set policy. It basically inspect packets and filters them if they violate the policy.

Man in the middle (MITM) is when someone intercepts messages between hosts. MITM attack can occur by ARP poisoning which sends the network the hackers MAC address to an incorrect IP address, allowing messages to be sent to the hacker. Some MITM can be used for good such as mail proxy and SSL to prevent EXE files and sensitive datas from being transferred through mail. You can prevent MITM by encrypting data and messages before sending them out. Generally, you would encrypt the message with the receivers' public key then upon receival, the receiver can decrypt the message with their private key.

**Lab 2**

This week, we were assigned to complete Lab 2. Lab 2 consist of writing/modifying a python script to output informations about network activities logged in a .csv file. From this lab I learned how to determine what IP address are used for what services such as Email, DNS, Printer, Web Servers, etc. Also, I learned how to crunch the datas together to see which IP had the most activities, and what purpose the network is used for such as work, data center, or home. I learned how to reference a file in Linux for port and protocol numbers. Those files are /etc/services and /etc/protocols, respectively.

# Week 5

This week is about using various tools that we have learned, and new tools, to debug Windows kernel. The idea of debugging Windows kernal is observing if the Windows API has been hijacked in memory by malware rookits. Malware rootkits can be used to hide files from Windows Explorer by hijacking the Windows API that enumerates the files for users to view, filtering out the malicious files that it wants to hide, and returns the rest of the files back to the Application. The rootkit will changes the first jmp instruction in memory of a function it wants to hijack to a custom function written by the hacker. When that hijacked function runs, it will jump to the custom function, executes that set of instructions, then returns back to the original hijacked function. Performing kernel debugger allows us to observe what instructions are being ran.

The tools we covered this week are WinDbg, Tuluka, LiveKD, and Process Hacker.

WinDbg - Can be used to add breakpoints and step through a thread using Kernel Debugger tool in WinDbg.
Tuluka - An AntiRootKit that identifies any hooks by any programs and drivers, and displays the original and patched memory addresses of the instructions.
LiveKD - An application that sits ontop of WinDbg and kd but provides live updates. Can create memory dumps for analysis

**Steps to patch a hooked API**
1. Use Tuluka to determine which API is hooked, note the API, original address, and the new address
2. Use LiveKD type "dps" and search for the API that looks out of bound and note the offset address
3. Go to Memory View and type in the address/offset
4. Rewrite the new address with the original address noted from Tuluka
Or just run the fix on Tuluka to patch the memory for you.

# Week 4

This week is about discovering exploitations and what it can be used for. The primary tool used for this week is WinDbg.

**WinDbg**

WinDbg is used to disassemble the process to Assembly language. After starting up the process, attach a process so the debugger can connect to it, then you can input command line to do things.

![WinDbg](https://i.imgur.com/X9Z1tUz.png)

In the image above, the left window shows the disassembly code of the chosen process. The right window shows the list of modules and .dll imported by the process.

WinDbg Commands
```
Click View->Disassembly // Displays disassembly view of the process
r     // Displays the registers and its values
dd, da, du <memory address> // Used to view whats inside memory, ex. du poi(esp)
bp <address> // Adds a breakpoint at the address
bc * // Clears all breakpoints
t, p // Steps through the process. t stops into, p steps over
!teb // Displays the process info including the heap
!peb // Displays the thread info including the stack
!address // Displays the list address used by the process
.formats // Converts value to other forms
?1+1 // Simply does the math
lm // Display list of modules imported by process
k // View call stack and disassembly view
u eip L10 // Lists 10 first ten lines of disassembled instructions


!load byakugan
!pattern_offset 2000
s [start] [end] ff e4 // Searches from [start] address to [end] address 
                      // and returns the address that contains "ff e4", or "jmp esp"
```

# Week 3

This week we learned about the basics of malware defense, their attack vectors, and how to defend against them.

I thought this flowchart was prettying interesting. It shoulds the malware lifecycle in 4 stages: First Contact, Execution, Establish Presence, and Malicious Activity. First contact is how the malware is administered to the victim, either by email, USB, or by some exploit. Then execution refers to tricking, or exploiting a browser vulnerabilities, to run a script. Establish presences is how malware keeps itself alive after a simple reboot, or protected itself from anti-viruses. Then finally, the malicious activities refers to the end game of the malware such as fraud, extortion, or destruction.

![Malware Attack Vector Flowchart](https://i.imgur.com/yJdK0nY.png)

The diagram below shows the layer of defense against malware. The first and second layer starts with the network firewall to prevent unwanted (or known to be bad) hosts from sending or receiving messages from the internal network by blocking their IP's. The next layers are hosts firewalls where the hosts can block IPs that are known to be bad, or just undesirable. And then theres access control with are user authentication and privileges to the endpoint. The last piece is anti-malware which is used to actively block, look-for, and remove malware.

![Malware Defense Later](https://i.imgur.com/V4XEaLR.png)

**Yara**

Yara Editor: code.google.com/p/yara-editor

Yara is a tool used to scan files that contains a set of rules(or strings) defined by the user. The idea is to write a rule that searches for unique strings found in malware. Good rules consist of unique and short rules.

Below is an example for of a yara rule.

```yara
rule Badboy
{
 strings:
    $a = "win.exe"
    $b = http://foo.com/badfile1.exe
    $c = http://bar.com/badfile2.exe
    
 condition:
     $a and ($b or $c)
}
```

In the first lab, I wrote the yara rule below that captures all of the file in C:\Users\Admin\Desktop\malware\MalwareDefense\Class1\ Sample Group 1\. However, scanning System32 will also show one false positive which is file "mfc71.dll".

```yara
rule Lab1
{
 strings:
    $a = "KERNEL32.DLL"
    $b = "advapi32.dll"
    $c = "oleaut32.dll"
    $d = "user32.dll"
    
 condition:
     all of them
}
```

The yara rule is run by terminal...
```
C:\Users\Admin\Desktop\Tools\MalwareDefense\yara-2.1.0-win32\yara32.exe -p 10 -a 5 <yara path> c:\Windows\System32
```

For the second lab, the yara rule below will successfully capture all of the file under C:\Users\Admin\Desktop\malware\MalwareDefense\Class1\ Sample Group 2\ and will not capture anything under System32.

```yara
rule Lab1
{
 strings:
    $a = "DownloaderActiveX" nocase
    
 condition:
     all of them
}
```

Conclusion: Yara is about finding signatures, or strings, that is common to the set of bad files, but unique only to those set of files. As for creating the rule, we have to determine why the strings, or commonalities, exist and what their purpose is for.

**Cuckoo**

Cuckoo is the tool used to run a malware on the VM and logs all activies in a csv file located in C:\cuckoo\logs
To Run:
1. Copy the malware file to the desktop and rename it to "bad"
2. Run cuckoo by "$ cd C:\analyzer" then "$ analyzer.py"
3. Close the crash window then run FakeNet.exe
4. View the csv file in the logs to read its behavior (which is the same as Week 1)

# Week 2

This week is about forensics investigation, which is about extracting data and determining what happened to a system. We learned a couple tools to help extract and analyze data while preserving the integrity of the evidence. Some tools introduced in this lectures are: FTK Imager, Volatility, Yara, and Photorec.

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

**Timeline Creation and Analysis via Volatility**

MAC Time : Modified, Access, Creation time
$MFT (master file table) : database in which information about every file and directory on an NT File System (NTFS) volume is stored.
Tools: Volatility, Reg-Ripper

 1. $ volatility.exe -f <memory name> imageinfo //to get the profile name
 2. $ volatility.exe -f --profile=<profile> timerliner --output=body >> timeliner.txt
 3. $ volatility.exe -f --profile=<profile> mftparser --output=body >> mftparser.txt

**Data Recovery by Photorec**

Photorec is used to recovery files that are 'deleted' but the data still remains in the disk.

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

