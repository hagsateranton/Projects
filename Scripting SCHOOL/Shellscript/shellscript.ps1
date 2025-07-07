#Shellscript
#Anton Hagsäter
#2025-05-08
# Säkerhetsskript och härdning för Windows Server
# 
#definierar loggfiler samt plats
$logdate = Get-Date -Format 'yyyyMMdd'
$logfile = "C:\Logs\security_hardening_$logdate.log"

#ser till att log dir existerar
if (!(Test-Path -Path "C:\Logs")) {
    New-Item -ItemType Directory -Path "C:\Logs" | Out-Null #Skapar loggfilen om den inte finns
}

# Logging function menat att skriva tidstämplade meddelanden till loggfilen
function Log{
    param(
        [string]$message
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "$timestamp - $message"
    Add-Content -Path $logfile -Value $entry
}
Log "===== Security Hardening Script Started =====" #Loggar starten av skriptet

#---------------------brandvägg----------------------------------

Log "Checking and configuring Windows Firewall..." #Loggar att brandväggen konfigureras och kontrolleras

#Sätter igång brandväggen och aktiverar den för alla profiler
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True #Tillåter brandväggen för domän, privat och offentliga profiler samt loggar funktionen
Log "Enabled Windows Firewall for all Profiles."

#Tar bort alla onödiga regler i brandväggen igenom att definiera en lista med tillåtna regler och sedan filtrerar
$allowedRules = @("Remote Desktop", "HTTPS-In")
Get-NetFirewallRule -Direction Inbound | 
Where-Object {
    $_.DisplayName -notin $allowedRules
} |
ForEach-Object { #tar bort alla regler som inte är med i listan av tillåtna regler
    Log "Disabling-NetfirewallRule -Name $_.Name"
    Disable-NetFirewallRule -Name $_.Name
}

#Ser till att RDP och HTTPS är aktiverade
foreach ($rule in $allowedRules) {
    try {
    $fwRule = Get-NetfirewallRule -DisplayName $rule -ErrorAction Stop #avslutar om regeln inte hittas
    if ($null -eq $fwRule) { #Kontrollerar att regeln finns och loggar om den inte finns
        Log "Warning: Required rule $rule not found. Creating rule."
        New-NetFirewallRule -DisplayName $rule -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389 #Skapar regeln om den inte finns
    } elseif ($fwRule.Enabled -ne $True) { #Kontrollerar att regeln är aktiverad och loggar den om inte
        Enable-NetFirewallRule -DisplayName $rule #aktiverar regeln
        Log "Enabled required rule: $rule." #Loggar att regeln är aktiverad
    } else {
        Log "Verified rule is enabled: $rule." 
    }
    } catch {
        Log "Error processing rule: $rule. Error Details: $_" #Loggar fel som uppstår under processen
    }
}
Log "===== Firewall configuration completed =====" #loggar att brandväggen är konfigurerad"


# ------------------Defender---------------------

Log "Checking Microsoft Defender status..." # loggar att den kontrollerar status för microsoft defender

# Kollar att Defender är igång
$defenderStatus = Get-MpComputerStatus
if ($defenderStatus.AntispywareEnabled -and $defenderStatus.RealtimeProtectionEnabled) {
    Log "Microsoft defender is active and real time protection is enabled." # loggar att defender är aktiv
    } else {
    Log "WARNING: Microsoft Defender is not active or real time protection is not enabled." #loggar att defender inte är korrekt aktiverad
}

# Letar efter uppdateringar
if ($defenderStatus.AntivirusSignatureAge -gt 1) {
    Log "Definitions are outdated. Attempting update..." #loggar är defintionerna är utdaterade och försöker uppdatera
    try{
        Update-MpSignature -UpdateSource MicrosoftUpdateServer #uppdaterar
        Log "Definitions updated"
} catch {
    Log "Error updating definitions $_"
}
} else {
    Log "Definitions are up to date"
}

#startar full scan
try {
Start-MpScan -ScanType Fullscan | Out-Null #startar en full scan och ignorerar output
Log "Full Defender Scan Started." #loggar att en full scan har startats
} catch {
    Log "Error Starting full scan: $_" #loggar om fel uppstår
}

#----------------------------Adminstration

if (-not (Test-Path -Path .\approved_users.txt)) {
    Log "Error: approved_users.txt file not found. Proceeding without user validation."
    $approvedUsers = @() # skappar en tom array för att undvika problem med forloops
} else {
    $approvedUsers = Get-Content -Path .\approved_users.txt
    if ($approvedUsers.Count -eq 0) {
        Log "Warning: approved_users.txt is empty. Proceeding without user validation."
    } else {
        Log "Approved users loaded."
    }
}

# hämtar nuvarande användare
try {
$adminGroup = [ADSI]"WinNT://./Administrators,group" #hämtar nuvarande administratörs grupp
} catch {
    Log "Error could not retrieve admin group: $_" #loggar om det inte går att hämta administratörsgruppen
    exit # avslutar om den inte kan hämta admin group
}
$members = New-Object System.Collections.Arraylist #skapar en lista för att lagra användare
$adminGroup.Invoke("Members") | ForEach-Object {
    $member =$_.GetType().InvokeMember("Name", 'Getproperty', $null, $_, $null) #hämtar användarna i admin gruppen
    [void]$members.Add($member) #lägger till användarna i en lista
}
#validerar admins
foreach ($user in $members) {
    if ($approvedUsers.Count -eq 0) {
        Log "Skipping user validation as no approved users were found in txt file."
        break
    }

    if ($user -notin $approvedUsers) {
        try {
            Log "Removing unauthorized user: $user" #loggar att en oauktoriserad användare har hittats
            net localgroup Administrators $user /delete #tar bort oauktoriserad användare från administratörsgruppen
        } catch {
            Log "Unexpected Error: Could not remove unauthorized user $user - $_" # loggar om det inte går att ta bort användaren
        }
    } else {
        Log "Verified approved user: $user" #loggar att användaren är godkänd
    }
}
#---------------------------------audit

#tar bort inaktiva användare (mer än 90 dagar)
$thresholdDate = (Get-Date).AddDays(-90) #definerar gräns på 90 dagar
Get-LocalUser | Where-Object {
    $_.Enabled -eq $true -and $_.LastLogon -ne $null -and $_.LastLogon -lt $thresholdDate #kollar om användaren är inaktiv och inaktiverad
} | ForEach-Object { #loopar igenom användarna
    Disable-LocalUser -Name $_.Name #inaktiverar användaren
    Log "Disabled inactive user: $($_.Name)" #loggar att användaren har inaktiverats
}

# -------------------------- Stänger av osäkra eller utdaterade tjänster/protocol

Log "Disabling Unsafe Protocols and services..." 
#Stänger av SMBv1 Via Registry och features
try {
    $smb1Status = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" #kollar status på SMBv1
    if ($smb1Status.State -eq "Disabled") {
        Log "SMBv1 already disabled." #loggar att SMBv1 redan är avstängt"
    } else {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Force #stänger av SMBv1
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue #stänger av SMBv1
    Log "SMBv1 disabled." #loggar att SMBv1 har stängts av
    }
} catch {
    Log "Error disabling SMBv1: $_" #loggar om det inte går att stänga av SMBv1
}

#-------------------------------------- Stänger av och disablar onödiga tjänster

Log "Checking for insecure unnecessary services..." #loggar att den kollar för osäkra tjänster
$badServices = @("Telnet", "FTPSVC", "SNMP", "RemoteRegistry") #definerar en lista med osäkra tjänster
foreach ($svc in $badServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue #hämtar tjänsten
    if ($service) {
        if ($service.Status -eq "Running") {
            Stop-Service -Name $svc -Force #stoppar tjänsten om den är igång
            Log "Stopped Service $svc" #loggar att tjänsten har stoppats
        }
        Set-Service -Name $svc -StartupType Disabled
        Log "Disabled Service $svc" #loggar att tjänsten har inaktiverats
    } else {
        Log "Service not found: $svc" #loggar att tjänsten inte hittades
    }
}

Log "Service audit cleanup completed." #loggar att tjänstgranskningen är klar

#------------------------------------------------------- Disk check lets goooo

Log "Checking disk space on system drive..."

try {
    $drive = Get-PSDrive -Name C -ErrorAction Stop
    if ($null -eq $drive.Free -or $null -eq $drive.Used) {
        Log "Error: Unable to retrieve disk space information."
        return
    }
    $freePercent = ($drive.Free / ($drive.Used + $drive.Free)) * 100
    Log "Free space on C: is $([math]::Round($freePercent, 2))%"
} catch {
    Log "Error retrieving disk space information: $_"
    return
}

$archivePath = "C:\TempArchive_$(Get-Date -Format 'yyyyMMdd_HHmm')"
if ($freePercent -lt 15) {
    if (-not (Test-Path -Path $archivePath)) {
        try {
            New-Item -ItemType Directory -Path $archivePath -Force | Out-Null
        } catch {
            Log "Error creating archive directory: $_"
            return
        }
    }
    Log "Low space detected. Archiving temp files to: $archivePath"

    $tempPaths = @("$env:TEMP", "$env:windir\Temp")
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            Log "Moving files from $path..."
            Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                try {
                    Move-Item $_.FullName -Destination $archivePath -Force -ErrorAction Stop
                } catch {
                    Log "ERROR moving $($_.FullName): $_"
                }
            }
        } else {
            Log "Temp path not found: $path"
        }
    }
    Log "Archiving complete."
} else {
    Log "Sufficient disk space available. No action needed."
}

#----------------------------Bitlocker-------------------------------
Log "Checking BitLocker encryption status..."

if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) {
    Log "BitLocker cmdlets not available. Skipping encryption step."
}

$bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" #hämtar status på bitlocker
if ($bitlockerStatus.VolumeStatus -eq "FullyEncrypted") { #loggar att bitlocker är igång
    Log "BitLocker is already enabled on C:."
} else { #om bitlocker inte är aktiverad så försöker den aktivera den
    try {
        Log "BitLocker not enabled. Attempting encryption..."  #loggar att bitlocker inte är aktiverad och försöker aktivera den
        Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -TpmProtector -UsedSpaceOnly -ErrorAction Stop #aktiverar bitlocker med TPM och krypterar bara den använda platsen
        Log "BitLocker encryption initiated on C: with TPM protector."# #loggar att bitlocker har aktiverats
    } catch {
        Log "ERROR: Failed to enable BitLocker - $_"
    }
}


#---------------FÄRDIGT HEHE -------------
Log "Security hardening complete."

Write-Host "`n========================="
Write-Host " Big Old Security Check complete "
Write-Host "========================="
Write-Host "Logg sparad som: $logFile" -ForegroundColor Green
Write-Host "`nResultat:" -ForegroundColor Cyan
Get-Content $logFile | Select-String "ERROR" -SimpleMatch | ForEach-Object {
    Write-Host $_.Line -ForegroundColor Red
}
Write-Host "`nOm du ser röda fel ovan, kolla loggfilen och gråt."
Write-Host "`nKlar! Servern är nu stenhård." -ForegroundColor Yellow
#Ingen tycker om windows :)