# Simulate Akira Ransomware tactics, techniques, and procedures (TTP) with atomic red team and some own tests to validate security controls

 Recommend to run it also without pattern based malware protection, to verify EDR behaviour based detections, otherwise pattern based AV will block most of the tools. An attacker who does obfuscation of these attack tools, wont be detected by pattern based av.
 Expect that attackers will turn off your EDR Solution like in steps 22-24, how do you detect and protect without EDR? running it without EDR will also test your system hardening settings like Windows Credential Dump Hardening settings like LSA Protect or Credential guard. 

 Prerequisite: https://github.com/redcanaryco/invoke-atomicredteam - works best with powershell 7


 see detailled descriptions of tests at github readme files for atomics for example for T1003: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md

References
 https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
 https://detect.fyi/akira-in-the-chang-way-server-ecosystem-re-vicitimization-a9011fbc6dff
 https://www.trendmicro.com/vinfo/tr/security/news/ransomware-spotlight/ransomware-spotlight-akira



Tests
# Atomic Test #1 - T1482 - Windows - Discover domain trusts with nltest
# Atomic Test #2 - T1069.001 - Basic Permission Groups Discovery Windows (Local)
# Atomic Test #3 - T1069.002 - Basic Permission Groups Discovery Windows (Domain)
# Atomic Test #4 - T1018 - Remote System Discovery with nltest
# Atomic Test #5 -T1057 - Process Discovery with tasklist
# Atomic Test #6 T1482 - Domain Trust Discovery
#  Test #7 T1046 - Network Service Discovery (advanced ip scanner)
# Atomic Test #8 T1016 - System Network Configuration Discovery on Windows
# Atomic Test #9 - T1003.001 - Offline Credential Theft With Mimikatz
# Atomic Test #10 - T1003.001 - Dump LSASS.exe Memory using ProcDump
# Test 11 - T1003.001 - Dump Credentials using Lazagne
# Test 12 - T1003.001 - Dump Credentials using esentutl.exe from Chrome 
# Atomic Test #13 - T1003.005 - Cached Credential Dump via Cmdkey
# Atomic Test #14 - T1547.009 - Create shortcut to cmd in startup folders
# Atomic Test #15 - T1053.005 - Scheduled Task Startup Script
# Atomic Test #16 - T1548.002 - WinPwn - UAC Bypass ccmstp technique
# Atomic Test #17 - T1558.003 - Rubeus kerberoast
# Atomic Test #18 - T1134.001 - SeDebugPrivilege token duplication
# Atomic Test #19 - T1021.002 - Copy and Execute File with PsExec
# Atomic Test #20 T1136.002 - Create Account: Domain Account - Username itadm
# Atomic Test #21 T1136.002 - Create Account: Domain Account - Powershell
# Atomic Test #22 T1562.001 - Impair Defenses: Disable or Modify Tools - Akira threat actors use BYOVD attacks to disable antivirus software
# Atomic Test #23 T1562.001 - Impair Defenses: Disable or Modify Tools - disable defender
# Atomic Test #24 - T1562.004 - Disable Microsoft Defender Firewall via Registry
# Atomic Test #25 - T1219 - Remote Access Software - AnyDesk Files Detected Test on Windows
# Test #26 - T1090 - ngrok Proxy Service
# Atomic Test #27 T1560.001 - Archive Collected Data: Archive via Utility - with Win-rar and password protected
# Atomic Test #28 T1048.003 - Exfiltration Over Alternative Protocol - FTP - Rclone
# Atomic Test #29 - T1567.002 - Exfiltrate data with rclone to cloud Storage - Mega (Windows)
# Atomic Test #30 - T1486 - PureLocker Ransom Note
# Test 31 - T1486 - Add Files with .akira File Ending + Akira Ransomnote
# Atomic Test #32 - T1490 - Windows - Delete Volume Shadow Copies with Powershell
