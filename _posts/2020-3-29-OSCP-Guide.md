---
layout: post
title: OSCP Guide
---

This is just another OSCP guide but it will be a very detailed one.

![_config.yml]({{ site.baseurl }}/images/oscpGuide/oscp.png)

## 1. Introduction

I am 39 years old computer engineer with 12 years enterprise level IT experience as sysadmin. I have been in cyber security for about 3 years mostly as a student. I had some experience with Kali Linux and general tools of penetration testing before starting PWK.

## 2. About Offensive Security

[Offensive Security](https://www.offensive-security.com/) is the most respected Cyber Security certification authority, at least for me. Their certifications are very well designed and has an absolutely top level acceptance in the professional field. Aside from being a certification/training provider, they also offer Professional Services such as Penetration Testing. One last thing they do is developing [Kali Linux](https://www.kali.org/) which is the industry standard for penetration testing.

## 3. About OSCP

[OSCP](https://www.offensive-security.com/pwk-oscp/) is the entry level certification of Offensive Security for Penetration Testers. Although it is named as an **entry level certification** and it really is, **penetration testing is NOT an entry level job.** It will require a wide range of background knowledge such as using linux, web, ftp, snmp, mail, active directory, dns, telnet servers, their client side tools, and tons of pentesting tools.

To not to get confused, I should inform you PWK(Penetration Testing with Kali Linux) is the course you take to be able to take OSCP exam.

While you are purchasing PWK, you will set a starting time for your course. You will get a link to download your course materials (PDF and video) and your username/password for VPN connection to the labs/forum account on your actual lab start time. There is no way to get materials before your lab start time since the PDF/videos and labs goes head to head. With the [PWK 2020 update](https://www.offensive-security.com/offsec/pwk-2020-update/) you get a 853 pages long PDF and 17+ hours of video tutorials.

You will be required to set an exam time during your lab time. OSCP exam consists of 2 phases with each is a day long. The first day, you will be given a new VPN pack to your very own 5 exam machines including:
* 1 Windows buffer overflow machine (25pts)
* 4 hackable machines (1x25pts, 2x20pts, 1x10pts)

On the second day you will need to write a professional pentest report while **you don't have access to your exam machines.** So, during the exam you need to take detailed screenshots of your solutions. In this second day of your exam, you have to submit your exam and lab reports to Offsec. You will get detailed information about how to submit your report(s)

If you happen to get at least 70 points from your exam and reporting, you will pass and obtain your **lifetime long** OSCP.

You can find the course syllabus [here](https://www.offensive-security.com/documentation/penetration-testing-with-kali.pdf)

## 4. About Kali Linux

Kali Linux is based on Debian and being developed by Offensive Security as a penetration testing distribution. Offensive Security is not suggesting Kali Linux to be used as a daily driver but there are some people who is doing against that suggestion. I am not such a person currently but I did used Kali as a main OS for about 3 months or so. If your hardware does well with it, I can suggest using Kali as a daily driver since with the [2020.1 update](https://www.kali.org/releases/kali-linux-2020-1-release/), default Kali installation comes with a non-root user which is a must for security if you are using it bare-metal. I have used Ubuntu as host operating system during my lab time and exam.

## 5. Environment Requirements

I will divide this section into subsections:

### 5.1. Host machine

While official suggestions by Offsec is low about your host machine for PWK/OSCP, I can suggest the following hardware on your host machine as minimum.

* Dual core CPU
* 8GB of memory
* Enough SSD capacity for your host and kali vm.
* Webcam on your host (must be on your host machine for exam, be it internal or external doesn't matter)

I used an MSI GL62 notebook with quad core I7 CPU, 24GB of memory, 500GB SSD and Geforce 940MX GPU with Ubuntu 18.04 Gnome version with full updates and propriatary drivers installed from Nvidia. I really like XFCE as desktop environment, but Gnome has better support for multiple monitors and easier sound output selection if you have more then one and in my case, I had been using an external 24" monitor with HDMI sound output.

I should also add your keyboard is important as well, since you will be typing commands during the labs and exam. Don't forget that you will read a lot, so have a good monitor.

### 5.1. Kali

Offensive Security officially supports Kali Linux to be run as a VM on VMWare Player/Workstation/Fusion. I did followed their guideline and used Kali on VMWare Workstation. While during my lab time, Offsec was suggesting their custom PWK build for the course and exam which was a 32bit version and had a few tools pre-installed, I did used my own 64bit 2019.4 Kali VM. I used my kali virtual machine with 4 cpu cores, 8GB memory and 100GB of disk space.

### 5.2. Note Taking

If you are using Linux like me, you have a few options for note taking and Offsec says [CherryTree](https://www.giuspen.com/cherrytree/) is a good option. I used CherryTree for note taking during the labs and exam and I am still happy with it. CherryTree saves your notes as a single file and it can encrypt the file if you wish. I saved my CherryTree file on my google drive and set CherryTree to automatically save every minute. I also copied my CherryTree file to another place every week as a backup. If you wonder, I use [InSync](https://www.insynchq.com/) for google drive synchronization on Linux. (Shame on you google for still preparing a google drive client for linux for at least 3 years now). You can use [Mega](https://mega.nz/) for free both on Kali and almost all other Linux distro's if you wish.

![_config.yml]({{ site.baseurl }}/images/oscpGuide/cherry.png)

### 5.3. Screenshoot Tool

It's required during the labs and exam to have a lot of screenshot so you need a good one. Ubuntu 18.04 still have Shutter[link] in it's official repositories which doesn't exist in Kali's. Shutter is able to automatically save the screenshoot as a file and copy it to clipboard.  Just set a keyboard shortcut for **`shutter -s`** and have fun with it.

On Windows, you can use [OneNote desktop application](https://go.microsoft.com/fwlink/?linkid=2110341) both for taking notes and screenshots. You can change the default shortcut for screenshot taking using [this guide](https://www.winhelponline.com/blog/onenote-screen-clipping-shortcut-key-change/).

It's also possible that you can use Evernote on Windows. If you are on Linux, you can use [NixNote2](https://github.com/robert7/nixnote2/releases) as EverNote client. Make sure to set auto sync.

![_config.yml]({{ site.baseurl }}/images/oscpGuide/nixnote2.png)


### 5.4. Terminal Application

Since you will spend a lot of time on terminal, I highly suggest to have a good terminal application. I am pretty sure you have a lot of options but I am aware of 2 both are available on Kali repositories.

* tmux
* terminator

I used and suggest tmux, it's learning curve might take a bit but believe me, you will use it on your whole pentesting career. Tmux has a handful set of plugins [here](https://github.com/tmux-plugins). Tmux settings can be changed by modifying ~/.tmux.conf file, you can find my version of it [here]({{ site.baseurl }}/images/oscpGuide/tmux.conf). If you decide to use my conf file dont forget 2 things:

* Change the name of the file to **.tmux.conf**
* Install or comment out plugins in the **List of Plugins section.** (tpm, tmux-sensible, tmux-cpu, tmux-logging, tmux-yank)

Tmux has a lot of advantages over terminator such as saving session logs and searching through command output which can help you tremendously.

### 5.5. Documentation

You can prepare a lab report during your lab time. It will have solutions to the exercises in the PDF and at least 10 lab machines with different attack vectors. A lab report is not a must but should be done by everyone for a few reasons:

* You can get up to valuable 5 points in your exam by preparing the lab report. You can never know if you will need that points to pass.
* You will have to prepare exam report after your exam and having prepared a lab report will give you a template for exam report. It will be a good practice.
* Writing your findings and steps is a very good learning way.
* You will learn important steps of solving machines and when to take screenshots during labs.

Offensive Security provides templates for both Libre Office(ODT) and Microsoft Word(DOC), I used the ODT file since I use Linux as my host machine. Do NOT forget to export both exam and lab reports as **pdf** before submitting.

## 6. Discord
Offsec has a discord server that you can join to keep you updated. I am a member of InfoSec Prep discord server and highly suggest to join it. Here is the link to join [InfoSec Prep](https://discord.gg/QwqePB9). InfoSec Prep channel has a lot of OSCP holders and students that are quite helpful. There are also some Offsec guys on the server.

## 7. Pre-requirements

Although not a must, basic IT and linux knowledge will help you a lot during PWK/OSCP and can shorten your lab time requirements. Do not overthink about these requirements, it shouldn't take more then a month to get enough knowledge if you are completely new to pentesting. If you try yo be perfectly ready for PWK/OSCP, you will never be. Take a look at the resources section on this guide.

## 8. Labs

Since the PWK got updated at 11th February, there are now 75+ hackable machines on the labs within . Lab environment is shared along with limited number of students who has a portal for reverting machines. Each student has given 12 reverts per day (not for each machine but for whole lab per day). Although 12 might be looking low, I never used more then 8 reverts during my 60 days lab time. Also, you can ask Offsec support if you are out of revert.

Lab environment contains around 75 machines which are divided into a few different network segments. You will start hacking machines on student network and try to hack ones at admin network as a final goal. Note that IT, Developement and Admin networks are not directly accessible from your VPN connection while Student Network is and you are supposed to pivot through some dual homed machines in student network. You should check machine ip addresses carefully if you happen to root them. Along with proof.txt file some machines has network-secret.txt file that you can use on your web panel to access to reverting those network machines.

![_config.yml]({{ site.baseurl }}/images/oscpGuide/labdiagram.png)

Offsec lab environment is a simulation of a real corporate environment, network segments (VLANs) are a part of real life as well. Not all machines are equally hard and some lab machines requires information from other machines to be hacked. For example a credential you found on Machine A can be used on Machine B, so looting the machines you rooted is crucial. But how do you know what you can loot on owned machines? That's a skill you will need to learn during your lab time and it is equally required in real life. Generally speaking, look for files in user home directories, try to get hashes from windows hosts, check /etc/shadow file, application and database config files. I highly suggest to have usernames, passwords, hashes, username:password files and take note all of credentials you gathered for future use on different machines. You should also check arp cache of each machine after rooting to be able to detect related machines (arp cache gets filled once a machine talks to another), run tcpdump to see related machines, check web application's access logs etc.

As a general rule, you can use /usr/share/wordlists/rockyou.txt file to decrypt/crack hashes you found on the lab machines and you will be most likely successful with rockyou if the hash you found is supposed to be cracked. You can use johntheripper or hashcat for password cracking, I used hashcat with my low end Nvidia GPU which is still thousands times faster then john since john uses CPU to crack hashes/passwords. Only other wordlists you will need are on Seclists which I gave link on resources section.

You will mostly never need to bruteforce any user login page during your PWK but never forget to try default user/passwords like admin/admin admin/password and check the application default passwords from google.

## 9. Hints for Lab Machines

Offsec provides student forums where you can find useful information about the course. Forums also contains a section for lab machines but I generally suggest to avoid hints from the forums as much as possible. In order to get most out of PWK, you will need to do lots of research and you will get furious from time to time but believe me on this, frustration is normal while learning pentesting. Do not forget that you will be on your own on your exam, so try to avoid forum hints as much as you can since I have seen some detailed spoilers on the forums. You can go to Offsec support page and ask your questions on live chat where you won't be given easy answers and it'll help you find out the intended way while not killing your learning.

You can ofcourse use forums to find if you missed another path to root a machine after you rooted since there are generally more then one path to root machines on the labs. Each different path to root a machine will teach you something new. Since labs isn't a CTF, you should look to learn but not to get flags.

You can also use InfoSec Prep discord channel's lab machine channels to ask about lab machines. People will help you over DM but not in public as it's against the server rules.

## 10. Exam

All Offsec certification exams are proctored, you will need to sit and connect to your given proctoring software 15 minutes before your exam. Do NOT forget to have a valid ID for yourself which will be checked by the proctor.

As I have used Ubuntu Linux on my exam, I was afraid of Offsec support on proctoring software and asked support about it. They gave me testing accounts and the official guide for proctoring software but it was quite easy. It's just a chrome extension from official Google extensions page (no firefox support). You will sign in to the software, share your screen(s) and that's all.

Once you get you VPN connection pack and connect to it, read the exam portal carefully.

During the exam, you will be able to use whatever you can find on internet, take a look at your notes, watch tutorials on youtube or different places. Some tools that are not allowed on exam such as sqlmap are already listed in the [exam FAQ](https://www.offensive-security.com/faq/). Since this is going to be a 24 hour long exam, you are expected and allowed to take breaks, just let the proctor know before moving away from your desk and wait for confirmation. Once you are back, tell it to your proctor. You can take long breaks for eating and even sleeping. If you need a long break, tell it to your proctor, you may be asked to close your webcam. You should be alone on the room you are taking exam but if someone gets in the room, it won't cause you to get disqualified but Offsec states it will be noted. There is no need to worry for this rule since if kids gets in, it won't cause any damage and elders will know why they shouldn't.

It is your responsibility to have sustained power and internet connection. You may however move to a different place during your exam if you need to, so don't stress it much. I should say, I had long electricity breaks for 2 days in a row before my exam but it's fixed by the night.

## 11. Reporting

Once you have completed your exam, you will need to write a professional pentesting report just like you do in real life. You will have another 24 hours for reporting but during this time, you will NOT have access to exam machines. **You are supposed to take screenshots and notes during your exam.** While video recording of exam is NOT allowed, you can use scripts to save a screenshot every few seconds during your exam.

## 12. How was my Experience with the Labs and Exam

I purchased 60 days of lab time and started at 5th Jan 2020, before PWK v2 was released. As I didn't had enough funds to get update and lab extension, I stayed with the old materials/ labs. At first I wasn't happy with staying old versions but in the end, I managed to pass the exam on my first attempt and didn't had to pay at least 200$ more for updates. Honestly, I really think 200$ is well worth for the updates since there are more content to study and %50 more lab machines to play and learn with.

I watched only Buffer Overflow part of videos but read the full PDF and completed the exercises in my first 10 days an started to write most of my lab report. I studied around 5 hours on average per day during 60 days lab time which means 300 hours in total. %20 of lab time was spent on exercises and %80 on labs. Since the PWK v2 has more content, it's reasonable to spend 100 hours on PDF/videos and 400 hours on labs. Please note that, this numbers reflect my experience and everyone learns at different pace.

I have taken extensive notes and screenshots during my lab time and I highly suggest it to everyone. My note structure was as following:

![_config.yml]({{ site.baseurl }}/images/oscpGuide/notes.png)

You should have recon, proof, loot, priv esc sub-sections for each host on both labs and exam.

While I was doing exercises on the PDF, I used autorecon for each host that I had access to. I also did a full nmap scan of student network on a few overnights. When I was finished with the PDF, I had enough information about the machines on student network. First I checked the nmap output for an overview and started to hack machines. Note that, you shouldn't work on machines by IP order but try to figure out low hanging fruits. Figuring out the low hanging fruits is an important pentesting skill, so do it on your own but not by asking to others on any community channel.

Once I have rooted around 30 machines on student network and got 2 network secret files, I started learning about pivoting and applied it to access the Developeent and IT networks. I haven't touched to Admin network but in total I have rooted around 45 machines during my 2 months lab time. If you happen to hack all machines and still have lab time, try to start over without looking back to your notes.

Both on labs and exam, exploit-db is the most important resource for finding exploits. You can use it's web interface or use *`searchsploit`* command line tool on Kali.

Before the PWK, I had no information about how to exploit buffer overflows but everyone was saying it's the easiest part of exam and I agree with it. It's generally taking 1 hour to exploit the BOF machine on exam and BOF exploitation has a strict steps unlike hacking other machines. Before exam, I took detailed notes including BOF script at each step :

![_config.yml]({{ site.baseurl }}/images/oscpGuide/bof.png)

Like almost everyone else, I started by **reading the exam panel** and started autorecon on 2 20pts machines, then jumped to BOF machine. I think it took like 1,5 hour for me to get done with BOF machine and all 4 machine autorecon was completed by that time. My strategy for the exam was doing 2 20pts machine after BOF for enough points to pass (25 + 20 + 20 + 5pts from lab report). Well, I did BOF but got only low priv on both 20pts machines where I lost some confidence. Unlike most people said, I didn't do 10pts machine right after BOF and kept it as a confidence booster if things go wrong and I really appreciate that idea. Once I failed to own 20pts machines, I started 10pts machine and owned it in 30 minutes. Then in 1 hour I rooted a 20 pointer machine and achieved 70 points. At this stage I had like 14 hours left on my exam time, so started the 25pts machine and got low priv user in an hour.

Once I had like 10 hours left after some break, I had 80 points from exam and 5 points from lab report. I decided to write the exam report and it took around 3 hours for me to complete the report. I went back to privilege escalation on 25 pointer and got it in less then 1 hour. On my last 3 hours I worked on PE of last 20 point machine although I already had enough points to pass. I even used metasploit for privilege escalation of last machine but I couldn't and decided to end my exam 15 minutes before the timeout.

As you may noted, I haven't slept during my exam but got 95 points in the end and my exam report was almost ready. After ending my exam, I went to sleep for 7 hours and spent around 2 hours for adding the last privilege escalation I got and sending the lab/exam reports. I was feeling very comfortable at this point and unlike other people who said waiting for the exam result is the hardest part of PWK, I was doing fine on the waiting game.

It took 6 days for Offsec to give me the good news. I got the results on a sunday evening (Europe time), it was morning on Asian countries. It's known Offsec has Asian workers, so maybe one of them graded my exam or if it was a European/US grader, they are working on weekends.

![_config.yml]({{ site.baseurl }}/images/oscpGuide/exam.png)

## 12. Resources
Links here should be very helpful in your TRY HARDER journey and I highly suggest you to learn and get familiar with them before you start PWK.

* A must have recon tool by Tib3rius - <https://github.com/Tib3rius/AutoRecon>
* Tib3rius's Udemy courses for privilege escalation on Linux and Windows - <https://www.udemy.com/user/tib3rius/>
* Tib3rius's pentesting guide - <https://github.com/Tib3rius/Penetration-Testing-Guide>
* TJNull's OSCP guide - <https://www.netsecfocus.com/oscp/2019/03/29/The_Journey_to_Try_Harder-_TJNulls_Preparation_Guide_for_PWK_OSCP.html>
* TJNull's OSCP like machine list from HTB and VulnHub - <https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159>
* Ippsec's videos - <https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA>
* InfoSec Prep Discord server - <https://discord.gg/QwqePB9>
* Seclists (can be installed using apt on Kali) - <https://github.com/danielmiessler/SecLists>
* All the things - <https://github.com/swisskyrepo/PayloadsAllTheThings>
* Hacktricks book - <https://book.hacktricks.xyz/>
* A lot of awesome cheat sheets by PentestMonkey - <http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet>
* Overthewire wargames - <https://overthewire.org/wargames/>
* Awesome privielege escalation scripts suite - <https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite>
* Linux Smart Enumeration Script - <https://github.com/diego-treitos/linux-smart-enumeration>
* Checklists - <https://github.com/netbiosX/Checklists>
* Tmux - <https://github.com/rothgar/awesome-tmux>
* Windows exploit suggester - <https://github.com/AonCyberLabs/Windows-Exploit-Suggester>
* Linux exploit suggester - <https://github.com/jondonas/linux-exploit-suggester-2>
* Public pentesting reports - <https://github.com/cure53/public-pentesting-reports>
* Lazagne to get clear text passwords - <https://github.com/AlessandroZ/LaZagne>
* Awesome buffer overflow guide - <https://github.com/justinsteven/dostackbufferoverflowgood>
* Cheat sheets - <https://github.com/OlivierLaflamme/Cheatsheet-God>
* Windows privelege escalation checking tool - <https://github.com/GhostPack/Seatbelt>
* Powershell scripts - <https://github.com/samratashok/nishang>
* Windows kernel exploits - <https://github.com/SecWiki/windows-kernel-exploits>
* Linux kernel exploits - <https://github.com/SecWiki/linux-kernel-exploits>
* Static binaries - <https://github.com/andrew-d/static-binaries>
* Pentesterlab, awesome web app courses - <https://pentesterlab.com/>
* GTFObins - <https://gtfobins.github.io/>
* Linux shell help - <https://explainshell.com/>
* OSCP gold mine - <http://0xc0ffee.io/blog/OSCP-Goldmine>
* Metasploit guide by Offsec - <https://www.offensive-security.com/metasploit-unleashed>

## 13. Other things
* Always drink enough water not only during PWK, but all your life.
* You need to be a good researcher to be able to successful in Cyber Security field, read command outputs and especially errors carefully
* Do not forget to spend at least 30 minutes for walking everyday, healthy body is a must
* If you get frustrated during labs/exam, try to get away for at least 5 minutes to chill down. Once you are back to study, try to make a list of information you got about the target machine, re-read the recon results.
