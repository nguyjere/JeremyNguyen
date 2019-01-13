### Welcome to my CS 373 Defense Against the Dark Arts Page!

Each week I will submit a post about my reflections on what I learned from the weekly lectures or labs of CS373. This includes ideas, concepts, tools, or whatever conclusions I came to.

## Week 1

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
 
 Using FakeNet, the malware wants to connect to s www.hisunpharm.com, static.naver.net, and timeless888.com, which are also found in the string dump of evil.exe
 
 Knowning this, I think the easiest way to remove this malware is to deleted the c:\ntldrs folder, remove all the auto tasks in Task Scheduler, delete C:\Users\Admin\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\KLTT2YG3\pao[1].exe and  C:\Program Files\tongji2.exe. Then also revert the hosts file if possible, and change its permission back from 'everyone'.


