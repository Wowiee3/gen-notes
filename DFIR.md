# Reading email
## .ost files
.ost files can be found under `C:\Users\[username]\Appdata\Local\Microsoft\Outlook`
### Parsing .ost files
- Use pffexport (Linux) to create a dump file of all emails 
	`pffexport [file]`
	- The interesting stuff is under the IPM_SUBTREE folder

# Application information
## Prefetch files
Prefetch files are used to speed up the start up time of programs through caching.
They can be found in `C:\Windows\prefetch`
Prefetch files can be used to:
- Find when apps were created/modified/last accessed
- Find size of the app
- Find how many times the app was run/when
- Find other files referenced by the app
### Parsing prefetch files
- Use PECmd.exe from Eric Zimmerman's Tools
	`.\PECmd -f "[path]"`
	- The output should show all the information mentioned above


# Internet History
## Edge 
`C:\Users\[user]\Appdata\Local\Microsoft\Edge\User Data\Default\History`

## Firefox
### Visited Links
`C:\Users\[user]\Appdata\Roaming\Mozilla\Firefox\profiles\[profile]\places.sql`
### Search History
`C:\Users\[user]\Appdata\Roaming\Mozilla\Firefox\profiles\[profile]\formhistory.sql`

# General Tools
## Chainsaw Search
Fast search tool for Windows artefacts useful if you want to find all instances of a pattern
`./chainsaw search "[pattern]" [path]`
- You might want to use `--skip-errors` if any are encountered
	Useful things to look for in the chainsaw output
	- `RuleName`: technique ids and technique names for attacks
	- `QueryName`: to find website queries
	- `TargetFilename`: files used

## dnSpy
Debug and disassemble .NET programs

## Monodis
If you want to quickly disassemble programs written with the .NET framework from the terminal:

```shell
> monodis --output=[filename] [file].exe
```

## Unpac.Me
Automated malware unpacking and artifact extraction