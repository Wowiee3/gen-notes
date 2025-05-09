[Windows Security Event Logs ID's](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)

| Code | Description                                              |
| ---- | -------------------------------------------------------- |
| 4625 | Failed logon                                             |
| 4624 | Successful logon (sus if service account was RDP'd into) |
| 4732 | Member was added to security-enabled local group         |
| 4733 | Member was removed from security-enabled local group     |
# Elastic

**Note:** It seems that Elastic follows Malaysian timezone. So when HTB asks for a date and your answer returns wrong, try putting the date of the day before.

winlog.event_data.SubStatus 0xC0000072: Disabled user
winlog.logon.type = RemoteInteractive: RDP logon
related.ip.keyword: ip of computer who RDP'd
winlog.event_data.MemberSid.keyword: which user is added/removed from group
group.name.keyword: ^^ to/from which group?
event.action.keyword: what was the action
host.name.keyword: on which machine did the action take place

**KQL Query to exclude computer accounts**
```
NOT user.name: *$ AND winlog.channel.keyword: Security
```

**KQL Query to search for fields containing value**
```
user.name: admin*
```

## Creating Dashboards
Specify the date range first @ the calendar

![[Pasted image 20250416174720.png]]
1. Filter
2. Index: the data set you wanna use
3. Search bar: double check fields in your data set
	*tip: use user.name.keyword instead of user.name*
	*tip 2: but don't use .keyword for KQL queries*
4. Type of visualization

After selecting ur visualization you need to configure what field goes where and the metrics
Don't forget to click save and return