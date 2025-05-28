**YARA:** Good at file and memory analysis + pattern matching
**SIGMA:** Good at log analysis and SIEM

## Yara
Commonly used for identifying malware samples and detecting IOC's

### Using YARA

```shell
> yara [rulename].yar [filename]
```

Use `--print-strings` to find matching strings
#### Format:
```yara
import "imports"

rule my_rule {

    meta:
        author = "Author Name"
        description = "example rule"
        hash = ""
    
    strings: 
        $string1 = "test"
        $string2 = "rule"
        $string3 = "htb"

    condition: 
        all of them
} 
```

**import:** any modules you wanna use for the rule.

**condition:** context of the files to be matched (e.g. all of them means that all strings have to be present to trigger the match)
Another condition can be file size, or file offset

#### Useful conditions

| Condition              | Value        | Description                                                                                      |
| ---------------------- | ------------ | ------------------------------------------------------------------------------------------------ |
| all of them            | -            | all values have to be present                                                                    |
| filesize               | < , > , ==   | specified the filesize                                                                           |
| uint16(0)              | == [value]   | checks the first 2 bytes (magic number). you can adjust this offset by specifying the hex offset |
| uint16(0)              | == `0x5A4D`  | Check if first 2 bytes are MZ (true for Windows PE files)                                        |
| pe.imphash()           | == [imphash] | checks the imphash. needs pe import                                                              |
| pe.number_of_sections  | ==, >, <     | self explanatory                                                                                 |
| pe.number_of_resources | ==, >, <     | self explanatory                                                                                 |
| 1 of/[number] of       | ($x*)        | where variables start with $x                                                                    |
| 1/[number] of them     | -            | requires number of strings from all variables                                                    |
| -                      | and, or      | you can use operators like these as well                                                         |

**hash:** hashes of the sample you used as references as you developed the rule

**$string:** these are actually variables, you can specify the type (e.g. ascii) after the string
#### Example (Wannacry):
```yara
rule Ransomware_WannaCry {

    meta:
        author = "Madhukar Raina"
        version = "1.0"
        description = "Simple rule to detect strings from WannaCry ransomware"
        reference = "https://www.virustotal.com/gui/file/ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa/behavior" 
    
    strings:
        $wannacry_payload_str1 = "tasksche.exe" fullword ascii
        $wannacry_payload_str2 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $wannacry_payload_str3 = "mssecsvc.exe" fullword ascii
    
    condition:
        all of them
}
```

#### Example (Detecting UPX):
```yara (upx_packed.yar)
rule UPX_packed_executable
{
    meta:
    description = "Detects UPX-packed executables"

    strings: 
    $string_1 = "UPX0"
    $string_2 = "UPX1"
    $string_3 = "UPX2"

    condition:
    all of them
}
```

### Developing YARA Rules
#### Using yarGen
You can use [yarGen](https://github.com/Neo23x0/yarGen) as an automatic YARA rule generator. It's useful because it already comes with a database of "good" strings and opcodes so you don't accidentally mark something benign.

```shell
> python3 yarGen.py -m [malware sample directory] -o [rulename].yar
```
#### Manually
Gather your IoC's. Examples:
- strings
- imphash
- filesize

#### Using the pe module
The PE  module allows you to use functions to check for more specific details of PE files.
Reference for the module: [readthedocs](https://yara.readthedocs.io/en/stable/modules/pe.html)

#### Using the math module
You can use math.entrophy to calculate the entrophy of a file.

**Example:**
```yara
import "pe"

rule your_rule {
...
condition:
	pe.imphash() == "[imphash]"
}
```

### Using YARA for Memory Forensics
It's best used alongside existing mem forensics frameworks (e.g. Volatility's yarascan plugin)

**Search for a specific rule in a memory dump**

```Shell
> vol.py -f [file] yarascan -U [pattern]
```

**Search for multiple YARA rules in a memory dump**

```Shell
> vol.py -f [file] yarascan -y [yarafile].yar
```

## Sigma
Signature format used to detect patterns in logs and SIEM systems. Usually written in YAML.

![[sigma_intro.webp]]

To use sigma rules across different systems, the Sigma converter (sigmac) or [pySigma](https://github.com/SigmaHQ/pySigma) is used. It transforms Sigma rules into queries/configs that are compatible with your platform.
#### Format:

```yaml
title: Potential LethalHTA Technique Execution 
id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471 
status: test 
description: Detects potential LethalHTA technique where "mshta.exe" is spawned by an "svchost.exe" process
references:
    - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
author: Markus Neis 
date: 2018/06/07 
tags: 
    - attack.defense_evasion 
    - attack.t1218.005 
logsource: 
    category: process_creation  
    product: windows
detection:
    selection1: 
        ParentImage|endswith: '\svchost.exe'
        Image|endswith: '\mshta.exe'
    condition: selection1
falsepositives: 
    - Unknown
level: high
```

**id:** Globally Unique Identifier ([randomly generated UUID](https://www.uuidgenerator.net/version4))
**status:** Stable, test, experimental, deprecated, unsupported
**tags:** MITRE tactics/techniques or other keywords
**logsource:** describes log data on which the detection rule is meant to be applied to (source of logs, platform, application)
	*category:* used to select all log files written by a certain group of products. The converter will use it to select indices (e.g. firewall, web, antivirus)
	*product:* used to select all outputs of a certain product (e.g. Windows Security, System, Application or apache, Windows Defender)
	*service:* select only a subset of a product's logs (e.g. sshd, applocker)
**detection:** search identifiers
	*selection:* search identifier lists. can be named differently. There are two formats for lists:
		fieldname|modifier:
			- value1
			- value2
			- value3
		This separates each value with a logical OR
		The other format is:
		fieldname|modifier: 'value'
		fieldname2|modifier2: 'value2'
		This separates each value in each list with a logical AND

| Modifier   | Description                          | Example                       |
| ---------- | ------------------------------------ | ----------------------------- |
| contains   | Adds * around the value              | CommandLine\|contains         |
| all        | Logical AND for all elements in list | CommandLine\|contains\|all    |
| startswith | Adds * to start                      | ParentImage\|startswith       |
| endswith   | Adds * to end                        | Image\|endswith               |
| re:        | Regular expression                   | CommandLine\|re:'\[String\]\s |
	*condition:* how the fields are related/filters.

| Condition                            | Example                                 |
| ------------------------------------ | --------------------------------------- |
| AND/OR                               | fieldname1 or fieldname2                |
| 1/2/all of them                      | all of them                             |
| 1/2/all of search-identifier-pattern | all of selection*                       |
| 1/2/all of search-id-pattern         | all of filter_*                         |
| Negation with 'not'                  | fieldname and not filter                |
| Brackets = order of operation        | selection1 and (fieldname1 or keyword2) |

**falsepositives:** known false positives
**level:** severity of triggered rule

## Kewl Github repos
### YARA
- [Yara-Rules](https://github.com/Yara-Rules/rules/tree/master/malware)
- [Open-Source-YARA-rules](https://github.com/mikesxrs/Open-Source-YARA-rules/tree/master)
- [The-DFIR-Report](https://github.com/The-DFIR-Report/Yara-Rules)
- [yarGen](https://github.com/Neo23x0/yarGen)
### Sigma
- [SigmaHQ](https://github.com/SigmaHQ/sigma/tree/master/rules)
- [joesecurity](https://github.com/joesecurity/sigma-rules)
- [SIGMA-detection-rules](https://github.com/mdecrevoisier/SIGMA-detection-rules)
- [The-DFIR-Report](https://github.com/The-DFIR-Report/Sigma-Rules)

#### Tips
- The Chainsaw tool can be used with SIGMA rules to search through log files
- ads