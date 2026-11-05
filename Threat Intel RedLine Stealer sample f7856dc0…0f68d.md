# Threat Intel: RedLine Stealer sample f7856dc0…0f68d

Nov 4, 2026 · @Mr.M

Only one public source ties this SHA256 to RedLine Stealer: an October 2026 static-triage write-up with no sandbox run, no C2 and no vendor confirmation. Treat the family call as medium-low confidence, and use the family-level process, artifact and network analytics below as the basis for rules, and confirm each one against your CAPE JSON.

## Sample profile

The public record for this exact hash is thin. The details below come from one static triage by an individual analyst ([GitHub write-up](https://github.com/kenmbogu/redline-stealer-triage-yara-detection), October 2026); the sample was never executed there.

| Attribute | Finding | Confidence |
| --- | --- | --- |
| SHA256 | f7856dc0d9a74e8bccfc47b55b24fe170f568b87feb7a8cb9c54fd81eee0f68d | Given |
| Size / type | 322 KB, PE32+ x64 GUI, Mono/.NET assembly | Medium (static) |
| Packing | Only 2 PE sections, asInvoker manifest, ConfuserEx-style obfuscation claimed | Low-medium |
| Notable strings | TelegramSessionParser, Discord, HttpWebRequest, GUID F935DC21, base64 blobs said to hold C2 | Low (not decoded) |
| Family | RedLine Stealer, inferred from the strings and stealer capability | Medium-low |
| C2 / botnet ID / dropped files | Not published | Unknown |

Two reasons for caution. First, the strings are generic: Discord and HttpWebRequest appear in many legitimate .NET apps, so the published 3-of-4 YARA rule will false-positive. Second, the size and architecture do not match classic builds: eSentire describes the plain payload as a 32-bit .NET binary of about 107 KB ([eSentire](https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-redline-stealer)). A 322 KB x64 file may be a packed or loader build, or a different .NET stealer. Your CAPE run should settle this.

## Behaviors to detect

These are family-level RedLine behaviors from published analyses. The sample's own strings (Telegram, Discord, HTTP) are consistent with rows 1 to 3, but only your CAPE output can confirm which apply to this file. Technique IDs follow [MITRE ATT&CK S1240](https://attack.mitre.org/software/S1240) where listed there, plus standard IDs for the rest.

| # | Behavior | ATT&CK | Telemetry that catches it |
| --- | --- | --- | --- |
| 1 | Reads browser stores: Chromium Login Data, Cookies, Web Data; Firefox cookies.sqlite ([source](https://nxg-7.github.io/posts/redline-stealer)) | T1555.003, T1539 | File-read events or object-access auditing on browser profile paths by a non-browser process |
| 2 | Targets chat and FTP/VPN apps: Discord, Telegram, Steam, FileZilla (recentservers.xml, sitemanager.xml), WinSCP, VPN clients ([Acronis](https://www.acronis.com/en-gb/cyber-protection-center/posts/redline-stealer-a-malware-as-a-service-info-stealer)) | T1555, T1552 | Same file-read telemetry on those app data folders |
| 3 | Crypto wallets: Electrum wallet folder and browser-extension wallets such as MetaMask ([SecurityScorecard](https://1275.ru/wp-content/uploads/2022/08/redline-stealer.pdf)) | T1657 | Reads of wallet directories and extension storage by an unsigned process |
| 4 | Host profiling and public-IP lookup: api.ipify.org ([Jafeeri](https://github.com/jafeeri/redline-stealer-analysis)), api.ip.sb ([Cyble](https://cyble.com/?p=6742)) | T1082, T1016 | DNS/proxy logs: lookup from an unsigned or recently dropped binary |
| 5 | File grabber driven by patterns received from C2, e.g. desktop files matching wallet, key, seed ([Oviche](https://oviche.github.io/2023/06/The-Analysis-of-Redline-Stealer/)) | T1005 | Burst of reads across user folders by one process |
| 6 | Runs inside a legitimate .NET host: AppLaunch.exe beaconing to C2 ([ThreatSpike](https://www.threatspike.com/blog/redline-infostealer-analysis-part-2/)); a signed Microsoft process hollowed in one 2026 sample ([Jafeeri](https://github.com/jafeeri/redline-stealer-analysis)) | T1055.012 | Sysmon 1 and 3: AppLaunch.exe or similar making external connections |
| 7 | C2 over WCF net.tcp (older builds) or REST over HTTPS (2024 builds) ([ESET](https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/)) | T1095, T1071.001 | Network sensor; see next section |
| 8 | Optional loader for follow-on payloads | T1105 | Child processes and new files after the stealer runs |
| 9 | Delivery by email attachment, Discord, malvertising, cracked games ([source](https://marwannour.github.io/Cyber-Blog/posts/RedLineStealer)) | T1566, T1204 | Mail gateway and download-then-execute chains |

## Process analytics: execution chain

No CAPE report was available to me, so the per-sample columns (process names, PIDs, command lines, mutexes) are blank. The stages below are the RedLine execution flow as published for other builds, in the order detection engineers should expect to see them. Fill the last column from your CAPE process tree.

| Stage | What the process does | Detection-relevant detail |
| --- | --- | --- |
| -1. Launch | User runs the .NET executable, often from a download, archive, email attachment or Discord link ([source](https://marwannour.github.io/Cyber-Blog/posts/RedLineStealer)) | Parent is typically explorer.exe, a browser, an archiver or an Office app; the repo triage reports an asInvoker manifest, so no elevation prompt |
| 2. Config decode | C2 address and botnet ID are stored encoded and decoded at run time with a hard-coded key ([S2W](https://medium.com/s2wblog/deep-analysis-of-redline-stealer-leaked-credential-with-wcf-7b31901da904)); one 2026 sample kept them encrypted in a resource ([Jafeeri](https://github.com/jafeeri/redline-stealer-analysis)) | No plaintext C2 in strings; the repo triage only reports base64 blobs, so expect the real C2 in the unpacked payload or memory |
| 3. Optional injection | Payload runs inside a legitimate .NET host: AppLaunch.exe was seen beaconing to C2 ([ThreatSpike](https://www.threatspike.com/blog/redline-infostealer-analysis-part-2/)); a 2023 chain used a first-stage EXE, an injector DLL and a dumped RedLine EXE ([Oviche](https://oviche.github.io/2023/06/The-Analysis-of-Redline-Stealer/)) | The network connection comes from the host process, not the original file; look for the original EXE exiting soon after launch |
| 4. C2 check-in | Checks whether the C2 is up, then exchanges host data and receives settings ([Oviche](https://oviche.github.io/2023/06/The-Analysis-of-Redline-Stealer/)); settings include flags such as ScanTelegramFlag, ScanVPNFlag, ScanWalletsFlag ([Cyble](https://cyble.com/?p=6742)) | The settings decide what is stolen, so two runs of the same file can differ; the stealer does not exfiltrate from CIS-country victims ([eSentire](https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-redline-stealer)) |
| 5. Host profiling | Public-IP lookup (api.ipify.org or api.ip.sb) and system details such as OS and processor ([Cyble](https://cyble.com/?p=6742)) | A short DNS lookup before the C2 connection |
| 6. Collection | Reads browser, chat, FTP, VPN and wallet data; a pattern-driven file grabber scans user folders ([Oviche](https://oviche.github.io/2023/06/The-Analysis-of-Redline-Stealer/)) | A burst of reads across many application folders by one unsigned process; see the artifact table below for paths |
| 7. Exfiltration | Collected data is sent to the C2 over the same channel ([ESET](https://www.welivesecurity.com/en/eset-research/life-crooked-redline-analyzing-infamous-infostealers-backend/)) | Larger outbound transfer to the same destination shortly after the reads |
| 8. Follow-on (optional) | Some builds download and run further payloads ([MITRE](https://attack.mitre.org/software/S1240)) | New files and child processes after the data theft |

The process sequence is more reliable for detection than any single indicator: DNS lookup, then C2 connection, then a burst of credential-store reads by the same process.

## Artifacts and file locations

The first group lists where RedLine reads data, which is where file-access telemetry should be watched. Paths use the standard Windows layout; the browser and wallet paths are named in the cited analyses, and the remaining app folders are the standard install locations for those programs.

| Target | Location | Basis |
| --- | --- | --- |
| Chrome cookies and credentials | %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\ (Cookies, plus Login Data, Web Data and Local State in the same profile) | Cookies path in [nxg-7](https://nxg-7.github.io/posts/redline-stealer); other files are the standard Chromium layout |
| Brave | %LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\ | [nxg-7](https://nxg-7.github.io/posts/redline-stealer) |
| Opera and Opera GX | %APPDATA%\\Opera Software\\ | Browsers named in [Cyble](https://cyble.com/?p=6742) and [SecurityScorecard](https://1275.ru/wp-content/uploads/2022/08/redline-stealer.pdf); path is the standard one |
| Firefox | %APPDATA%\\Mozilla\\Firefox\\Profiles\<profile>\\cookies.sqlite | [nxg-7](https://nxg-7.github.io/posts/redline-stealer) |
| Electrum wallet | %APPDATA%\\Electrum\\wallets | [SecurityScorecard](https://1275.ru/wp-content/uploads/2022/08/redline-stealer.pdf) |
| Browser-extension wallets (MetaMask, Coinbase, Binance Chain, Brave Wallet and others) | Extension storage inside each browser profile | Wallet list in [SecurityScorecard](https://1275.ru/wp-content/uploads/2022/08/redline-stealer.pdf) |
| FileZilla | recentservers.xml and sitemanager.xml under %APPDATA%\\FileZilla\\ | File names in [Acronis](https://www.acronis.com/en-gb/cyber-protection-center/posts/redline-stealer-a-malware-as-a-service-info-stealer); folder is standard |
| Steam | .ssfn sentry files in the Steam install folder | [Blackberry via marwannour](https://marwannour.github.io/Cyber-Blog/posts/RedLineStealer); folder is standard |
| Discord | Application cache under %APPDATA%\\discord\\ | [Acronis](https://www.acronis.com/en-gb/cyber-protection-center/posts/redline-stealer-a-malware-as-a-service-info-stealer); folder is standard |
| Telegram Desktop | Session data under %APPDATA%\\Telegram Desktop\\ (tdata) | Telegram targeting in [Cyble](https://cyble.com/?p=6742); folder is standard |

Artifacts the malware itself leaves behind are not established for this sample. Published reports are inconsistent: one 2023 sample used the folder %LOCALAPPDATA%\\SystemCache ([Oviche](https://oviche.github.io/2023/06/The-Analysis-of-Redline-Stealer/)), and a CloudSEK overview mentions scheduled tasks or Run keys for persistence ([CloudSEK](https://www.cloudsek.com/knowledge-base/redline-stealer-malware)). Take created files, mutexes, registry keys and scheduled tasks from the CAPE behavior summary and dropped-files list, not from these.

## Indicators of compromise

Only the hash and the static strings belong to this sample. The reference rows come from other RedLine builds, are years old, and should be used as examples of what to extract, not as blocklist entries for this file.

| Type | Value |
| --- | --- |
| SHA256 | f7856dc0d9a74e8bccfc47b55b24fe170f568b87feb7a8cb9c54fd81eee0f68d |
| Type, size | PE32+ x64 GUI, .NET, 322 KB, 2 sections |
| Strings | TelegramSessionParser, Discord, HttpWebRequest, F935DC21 |
| C2 and botnet ID | Not published |
| Domain | api\[.\]ipify\[.\]org |
| Domain | api\[.\]ip\[.\]sb |
| IP:port | 194\[.\]36\[.\]177\[.\]124:39456 |
| IP:port | 62\[.\]182\[.\]159\[.\]86:65531 |
| IP:port | 135\[.\]181\[.\]49\[.\]38:36303 |
| SHA256 | 5b61b470d1dbecb7ba63e13ffb7306521b039e7fee38e49697faa4ea968e1070 |
| SHA256 | e3a3e1968e2ba0871b65da21f0808c2e676202cb3b0fed4cec7672ad5a99b0b1 |
| SHA256 | 0b2a29c761d03e5a4aed4f7cd175fa016ccdf431cfec45de04379965f3ae7564 |

One pattern holds across the reference C2 rows: ports are high and attacker-chosen (39456, 65531, 36303), so port-based network rules will not work. Match on protocol behavior and process context instead.
