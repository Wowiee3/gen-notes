Windows EVT logs can be viewed with the default Event Viewer program or using the Windows event log API.

### Types of logs

| Name               | Description                                  |
| ------------------ | -------------------------------------------- |
| Application        | Application errors                           |
| Security           | Security events                              |
| Setup              | System setup activities                      |
| System             | General system info                          |
| *Forwarded Events* | Event log data forwarded from other machines |
## Useful Windows Event Logs
### System Logs

| EventID | Event Name                | Description                                                                                                                                      |
| ------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1074    | System Shutdown/Restart   | When and why a shutdown/restart happened.                                                                                                        |
| 6005    | Event Log service started | Marks the time when the event log service started. Can signify bootup and can be used as a starting point for investigations.                    |
| 6006    | Event Log service stopped | Marks the time when the event log service stopped. Typically happens on shutdown. If this event happens abnormally it could mean something's sus |
| 6013    | Windows Uptime            | Occurs once a day, shows uptime of system. Shorter uptime = possible reboot, might be sussy                                                      |
| 7040    | Service status change     | Indicates change in service startup type. (manual/auto). Could indicate tampering.                                                               |

### Security Logs

| EventID     | Event Name                                                                     | Description                                                                                                      |
| ----------- | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| 1102        | Audit Log was cleared                                                          | Can be a sign of intrusion or covering tracks                                                                    |
| 1116        | Antivirus malware detection                                                    | Indicates when Defender detects malware.                                                                         |
| 1118        | Antivirus remediation activity started                                         | Indicates that Defender has begun to remove/quarantine detected malware.                                         |
| 1119        | Antivirus remediation successful                                               | What it says                                                                                                     |
| 1120        | Antivirus remediation failed                                                   | What it says. Uh oh.                                                                                             |
| 4624        | Successful logon                                                               | What it says.                                                                                                    |
| 4625        | Failed logon                                                                   | What it says.                                                                                                    |
| 4648        | Logon attempted with explicit credentials                                      | Triggered when a user logs in with explicit creds to run a program                                               |
| 4656        | A handle to an object was requested                                            | Triggered when a handle to an object (e.g. file, registry key, process) is requested.                            |
| 4672        | Special privileges assigned to a new logon                                     | Triggered whenever an account logs on with super user privileges.                                                |
| 4698        | A scheduled task was created                                                   | Can help detect persistence mechanisms.                                                                          |
| 4700 & 4701 | A scheduled task was enabled/disabled                                          | For detecting persistence or for sus stuff in general.                                                           |
| 4702        | A scheduled task was updated                                                   | ^^                                                                                                               |
| 4719        | System audit policy changed                                                    | Sign of tampering/covering tracks.                                                                               |
| 4738        | A user account was changed                                                     | Any changes made to accounts (privileges, group membership, account settings).                                   |
| 4771        | Kerberos pre-authentication failed                                             | Similar to failed logon but for kerberos specifically.                                                           |
| 4776        | Domain controller attempted to validate credentials for an account             | Tracks successful/failed attempts at credential validation by DC. Lots of fails = brute force                    |
| 5001        | Antivirus real-time protection has changed                                     | What it says                                                                                                     |
| 5140        | A network share object was accessed                                            | For identifying unauthorized access to network shares                                                            |
| 5145        | A network share object was checked to see whether client can be granted access | Someone attempted to access a network share. Frequent access could suggest an attacker trying to map out shares. |
| 5157        | Windows Filtering Platform blocked a connection                                | What it says. For identifying malicious traffic.                                                                 |
| 7045        | A service was installed on the system                                          | Possible malware installation.                                                                                   |


### Useful details found in logs

| Detail     | Description                                                                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| Logon ID   | ID, allows you to correlate that logon with other events sharing that ID                                                                            |
| New/OldSd  | New/Old Security Descriptors<br>More reference: https://uwconnect.uw.edu/it?id=kb_article_view&sysparm_article=KB0034194                            |
| Privileges | Privileges granted to a user after successful logon<br>More reference: https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants |

*Tip: always search up the Event ID and read its entry on the Microsoft website for more context*
### XML Queries
Filter Current Log > XML > Edit Query Manually
