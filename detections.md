# Splunk Detections

All searches run against index `ad_lab`, sourcetype `WinEventLog:Security`, with events forwarded from DC01.

## Alerts

### AD - Repeated Failed Logons
- **Schedule:** every 5 minutes (`*/5 * * * *`)
- **Time range:** last 15 minutes
- **Trigger:** number of results is greater than 0
- **Throttle:** 15 minutes
- **Severity:** Medium

```
index=ad_lab sourcetype="WinEventLog:Security" EventCode=4771
| eval src=replace(Client_Address,"^::ffff:","")
| stats count by src, Account_Name
| where count>=5
```

Event 4771 is a Kerberos pre-authentication failure (a wrong password for a domain account). Five or more from one source in the window is the same pattern the account lockout policy is built to stop.

### AD - Account Lockout
- **Schedule:** every 5 minutes (`*/5 * * * *`)
- **Time range:** last 15 minutes
- **Trigger:** number of results is greater than 0
- **Severity:** High

```
index=ad_lab sourcetype="WinEventLog:Security" EventCode=4740
| eval locked_user=mvindex(Account_Name,-1)
| table _time, locked_user, Caller_Computer_Name
```

Event 4740 records an account being locked out. Account_Name holds two values (the logging host, then the locked user), so `mvindex(...,-1)` selects the user.

## Dashboard panels

### Failed logons over time

```
index=ad_lab EventCode=4771
| timechart span=5m count
```

### Account changes

```
index=ad_lab (EventCode=4720 OR EventCode=4722 OR EventCode=4724 OR EventCode=4725 OR EventCode=4726)
| eval actor=mvindex(Account_Name,0), target=mvindex(Account_Name,-1)
| table _time, EventCode, actor, target
```

| Event | Meaning |
|---|---|
| 4720 | Account created |
| 4722 | Account enabled |
| 4724 | Password reset attempt |
| 4725 | Account disabled |
| 4726 | Account deleted |

## Prerequisite: audit policy

Account management events (4720 to 4726 and 4740) are only written when the *User Account Management* audit subcategory is enabled:

```powershell
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
```
