**Event:** an action occurring in a system or network.
*Examples*
- an email being sent
- a mouse click
- a connection

**Incident:** an event with negative consequences;
**Security Incident:** an incident with intent to cause harm
*Examples:*
- data theft
- funds theft
- unauthorized access
- installation of malware

**Incident Handling:** a set of procedures to manage and respond to security incidents
The incident handling team is led by an incident manager (e.g. SOC manager, CISO/CIO)
[NIST incident handling guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)

# Cyber Kill Chain
This describes how attacks happen. It consists of 7 stages.
1. Recon: information gathering
2. Weaponize: initial access technique is developed
3. Deliver: exploit is delivered
4. Exploit: exploit is triggered
5. Install: initial stager (dropper, backdoor, rootkit) is executed and running
6. C&C: remote access established
7. Action: attack objective is performed

Adversaries won't necessarily operate in a linear manner. Some steps can be repeated and stuff

# Incident Handling Process
Defender version of the cyber kill chain
1. Preparation
2. Detection and Analysis
3. Eradication and Recovery
4. Post-Incident Activity

This isn't necessarily linear as well

Incident handling has two main activities
- Investigating: discovering patient zero and create a timeline, determining the attacker's tools, documenting their actions and compromised systems
- Recovering: creating and implementing recovery plan
After this a report is created for the incident. This involves a 'lessons learned' section

## 1. Preparation
Preparing for security incidents
- Having incident handling team members
- Training the workforce
- Having policies and documentation
- Preparing tools
- Having a baseline (clean state) of the environment

Protecting against security incidents
- [DMARC](https://dmarcly.com/blog/how-to-implement-dmarc-dkim-spf-to-stop-email-spoofing-phishing-the-definitive-guide#what-is-dmarc) to protect against phishing
- Endpoint hardening (EDR)
	- Disable LLMNR/NetBIOS
	- Implement LAPS and removing unnecessary admin perms
	- Disable/configure PowerShell in ConstrainedLanguage mode
	- Enable Attack Surface Reduction (ASR) rules if using MS Defender
	- Whitelisting and blocking script files
	- Host based firewalls
- Network Protection (segmentation)
- Privilege identity Management
- MFA
- Vulnerability Scanning
- User Awareness Training
- AD Security Assessment
- Purple Team Exercises

### Policies and Documentation
- Having contact info of incident handling team, compliance, support, law, etc
- Incident response plan

### Tools
Some tools that could be helpful
- Forensic workstation
- Forensic acquisition tools
- Log analysis tools
- Network capture tools
- Chain of custody forms
- Ticket system
These tools can also be known as a jump bag

The documentation system should be independent of the main infrastructure in case the whole thing is compromised.
	You should assume from the beginning that the whole infra is compromised
	The same should be applied to communication channels

## 2. Detection and Analysis
Detecting and incident and figuring out what happened
Different levels of detection can be found at different layers of the network:
- Network perimeter (detected with firewalls and internet facing IDS's)
- Internal network (local firewalls, host IDS)
- Endpoint level (antivirus, EDR)
- Application level (application logs)

### Initial Investigation
Figure out some context before calling out
- Date and time of incident detection
- How it was detection
- What is the incident
- Impacted systems
- Who has accessed the systems and what they did
- Physical location, OS's, IP addrs, hostnames

After gathering these details you can figure out an incident response timeline.
The timeline should have the following information:
- Date
- Time
- Hostname
- Event description (e.g. tool was detected)
- Data source (e.g. antivirus)

### Other Questions to ask
- What is the impact?
- What are the exploit's requirements?
- Any critical systems affected?
- Any remediation steps?
- Is the exploit being used in the wild?
- Can the exploit spread/is it worm-like?

You should also create IOCs and gather artifacts and stuff ig

## 3. Containment, Eradication and Recovery
After the investigation is complete and you've understood the incident you can do this.

You can do short term containment to leave a minimal footprint to not alert the attacker
- Disconnecting system from network
- Modifying C2 DNS

Then long term containment
- Changing passwords
- Inserting host IDS
- Patches

Eradication takes place after this. Just get rid of whatever is causing the incident here (rebuild/backup)

Then the recovery stage, where you bring systems back to normal operation. Make sure to log and monitor compromised systems heavily in case attackers go for round 2.

## 4. Post-Incident Activity Stage
Here you document and report the incident and the lessons learned from it
Make sure the stakeholders know and stuff

### Report
- What happened and when
- Performance of the team dealing with the incident
- What can be improved?
- What actions were implemented?
- What preventative measures should be taken?
- What tools and resources are needed to detect similar incidents in the future?