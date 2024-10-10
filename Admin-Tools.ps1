#scripts by Emmanuel MARCEROU
$version=1.3

$scriptPath = $MyInvocation.ScriptName

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path),"-ConfFile ",('"{0}"' -f $ConfFile) -Verb RunAs
}Else{
  Write-Verbose "I AM (Ps>)ROOT"
}

# Déterminer si la session est en administrateur
#if ($PSSession.IsAdmin) {} else {Exit}

[System.Console]::Title = "ADMIN TOOLS v$version"
$host.ui.RawUI.ForegroundColor = 'Green'
$host.ui.RawUI.BackgroundColor = 'Black'

cls
Write-Host "ADMIN TOOLS v$version"
Write-Host ""
Write-Host "1.  Joindre un domaine"
Write-Host "2.  Installer ADDS"
Write-Host "3.  Installer DHCP"
Write-Host "4.  Installer RDS"
Write-Host "5.  Transferer les Roles FSMO"
Write-Host "6.  Transferer les Imprimantes"
Write-Host "7.  Transferer le DHCP"
Write-Host "8.  Transferer Fichiers et Dossiers"
Write-Host "9.  Exporter la liste des Groupes"
Write-Host "10. Exporter la liste des Utilisateurs"
Write-Host "11. Exporter la liste des Partages"
Write-Host "12. Exporter la liste des Imprimantes"
Write-Host "13. Exporter la liste des Parametres Reseaux"
Write-Host "14. Exporter la liste GPO"
Write-Host "15. Exporter la liste des Groupes, Utilisateurs, Partages, Imprimantes, Parametres Reseaux et GPO"
Write-Host "16. Scanner le Reseau Local"
Write-Host "17. Activer les VSS"
Write-Host "18. Reparer reseau"
Write-Host "19. Reparation Windows Update"
Write-Host "20. Reinitialisation mot de passe utilisateur"
Write-Host "21. Informations systeme"
Write-Host "22. Afficher le mot de passe du Wifi"
Write-Host "23. Desactiver Bitlocker"
Write-Host "24. Verifier les ports ouverts"
Write-Host "25. Nettoyage et optimisation Windows"
Write-Host "26. Exporter la liste des ordinateurs obsoletes"
Write-Host "27. Recherche des chemin long"
Write-Host "28. Activation Windows"
Write-Host "29. Lister les partages et droits"
Write-Host "30. Lister les partages et droits NTFS"
Write-Host "31. Lister Groupes et membres des groupes d'un AD"
Write-Host "32. Maintenance sur le disque dur"
Write-Host "33. Liste des 10 plus gros fichiers"
Write-Host "34. Forcer la synchronisation de l'heure NTP"
Write-Host "35. Vider le spooler d'impression"
Write-Host "36. Lister les comptes utilisateurs desactives d'un AD"
Write-Host "37. Quitter"
Write-Host ""
$choice = Read-Host "Faites un choix"
if ($choice -eq "1") {
cls
Write-Host "** Jonction a un domaine existant **"
Write-Host ""
$domainName=Read-Host "Nom de domaine"
$domainUsername =Read-Host "Utilisateur"
$domainPassword =Read-Host "Mot de passe"
Add-Computer -DomainName $domainName -Credential (New-Object System.Management.Automation.PSCredential ($domainUsername, (ConvertTo-SecureString $domainPassword -AsPlainText -Force)))
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "2") {
cls
Write-Host "** Installer les roles ADDS sur un controleur de domaine **"
Write-Host "Le serveur doit etre dans le domaine"
Write-Host ""
$domainName=Read-Host "domaine.com"	
Install-WindowsFeature AD-Domain-Services
Install-ADDSForest -DomainName $domainName
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "3") {
cls
Write-Host "** Installer un serveur DHCP **"
Write-Host ""
Install-WindowsFeature -Name DHCP -IncludeManagementTools -Restart
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "4") {
cls
Write-Host "** Installer les roles RDS sur ce serveur **"
Write-Host ""
Install-WindowsFeature -Name RDS-RD-Server -IncludeAllSubFeature
$obj = gwmi -namespace "Root/CIMV2/TerminalServices" Win32_TerminalServiceSetting
$obj.SetSpecifiedLicenseServerList("RD License Server FQDN")
$obj.SetLicensingType(4)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fServerEnablePrintRDR -Value 1 -Type DWORD
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fEnableRemoteFXAdvancedRemoteAppMode -Value 1 -Type DWORD
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fEnableRemoteFX -Value 1 -Type DWORD
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name fSingleSessionPerUser -Value 0 -Type DWORD
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1 -Type DWORD
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name SecurityLayer -Value 2 -Type DWORD
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name fAllowSecProtocolNegotiation -Value 1 -Type DWORD
Restart-Service -Name TermService -Force
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "5") {
cls
Write-Host "** Transferer les Roles FSMO de serveur a serveur **"
Write-Host "Le serveur destination doit avoir les roles ADDS et etre dans le meme domaine que le serveur source"
Write-Host ""
$CurrentDC=Read-Host "Ancien controleur de domaine"
$NewDC=Read-Host "Nouveau controleur de domaine"
$CurrentDCObject = Get-ADDomainController -Identity $CurrentDC
$NewDCObject = Get-ADDomainController -Identity $NewDC
Move-ADDirectoryServerOperationMasterRole -Identity $CurrentDCObject -OperationMasterRole SchemaMaster -Confirm:$false -Force
Move-ADDirectoryServerOperationMasterRole -Identity $NewDCObject -OperationMasterRole SchemaMaster -Confirm:$false
Move-ADDirectoryServerOperationMasterRole -Identity $CurrentDCObject -OperationMasterRole DomainNamingMaster -Confirm:$false -Force
Move-ADDirectoryServerOperationMasterRole -Identity $NewDCObject -OperationMasterRole DomainNamingMaster -Confirm:$false
Move-ADDirectoryServerOperationMasterRole -Identity $CurrentDCObject -OperationMasterRole PDCEmulator -Confirm:$false -Force
Move-ADDirectoryServerOperationMasterRole -Identity $NewDCObject -OperationMasterRole PDCEmulator -Confirm:$false
Move-ADDirectoryServerOperationMasterRole -Identity $CurrentDCObject -OperationMasterRole RIDMaster -Confirm:$false -Force
Move-ADDirectoryServerOperationMasterRole -Identity $NewDCObject -OperationMasterRole RIDMaster -Confirm:$false
Move-ADDirectoryServerOperationMasterRole -Identity $CurrentDCObject -OperationMasterRole InfrastructureMaster -Confirm:$false -Force
Move-ADDirectoryServerOperationMasterRole -Identity $NewDCObject -OperationMasterRole InfrastructureMaster -Confirm:$false
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "6") {
cls
Write-Host "** Transferer les imprimantes de serveur a serveur **"
Write-Host ""
$PrintersFile = "$env:USERPROFILE\Printers.xml"
Export-Printer -Name * -Path $PrintersFile
$DestComputer=Read-Host "Serveur de destination"
$DestPath = "\\$DestComputer\c$\temp\Printers.xml"
Copy-Item $PrintersFile -Destination $DestPath -Force
Invoke-Command -ComputerName $DestComputer -ScriptBlock {
Import-Printer -Path "C:\temp\Printers.xml"}
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "7") {
cls
Write-Host "** Transferer un serveur DHCP vers un autre serveur **"
Write-Host "Le role Serveur DHCP doit etre installe sur les deux serveurs"
Write-Host ""
$SourceServer=Read-Host "Serveur DHCP source"
$DestServer=Read-Host "Serveur DHCP destination"
$ExportFile = "C:\Temp\dhcpexport.xml"
$IPNewServerDHCP=Read-Host "Adresse IP du nouveau serveur DHCP"
Export-DhcpServer -ComputerName $SourceServer -File $ExportFile
Import-DhcpServer -ComputerName $DestServer -File $ExportFile -BackupPath "C:\Temp\dhcpbackup"
Add-DhcpServerInDC -DnsName $DestServer -IPAddress $IPNewServerDHCP
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "8") {
cls
Write-Host "** Transferer des fichiers et dossiers avec Robocopy **"
Write-Host ""
$Source=Read-Host "Chemin source"
$dest=Read-Host "Chemin destination"
$dirs=Read-Host "Repertoires separes par un |"
$dirs.Split("|") | ForEach {
$fullsource=$source + "\" + $_
$fulldestination=$dest + "\" + $_
robocopy $fullsource $fulldestination  /E /SEC /COPYALL /R:10 /W:5 /V /ETA /LOG+:robocopy.log
}
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "9") {
cls
Write-Host "** Exporter la liste des Groupes de l'AD **"
Write-Host ""
Import-Module ActiveDirectory
$outputFilePath = ".\Liste des groupes.txt"
$groups = Get-ADGroup -Filter *
$groups | Select-Object Name | Sort-Object Name | Out-File $outputFilePath
Write-Host ""
Write-Host "La liste des groupes à été exporté vers $outputFilePath."
Write-Host ""
Write-Host "Operation terminee."
pause
} elseif ($choice -eq "10") {
cls
Write-Host "** Exporter la liste des Utilisateurs de l'AD **"
Write-Host ""
Import-Module ActiveDirectory
$OU=Read-Host "OU=Users,DC=domaine,DC=com"
#$OU = "OU=Users,DC=example,DC=com"
$Users = Get-ADUser -Filter * -SearchBase $OU
$Users | Select-Object Name, SamAccountName, EmailAddress | Export-CSV -Path ".\Liste des Utilisateurs.csv" -NoTypeInformation
Write-Host ""
Write-Host "Resultat enregistre dans Liste des Utilisateurs.csv"
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "11") {
cls
Write-Host "** Exporter la liste des Partages **"
Write-Host ""
$shares = Get-SmbShare
$shareList = @()
foreach ($share in $shares) {
    $shareList += [PSCustomObject]@{
        Name = $share.Name
        Path = $share.Path
        Description = $share.Description
        MaximumAllowed = $share.MaximumAllowed
        CachingMode = $share.CachingMode
        FolderEnumerationMode = $share.FolderEnumerationMode
    }
}
$shareList | Export-Csv -Path ".\Liste des Partages.csv" -NoTypeInformation
Write-Host ""
Write-Host "Resultat enregistre dans Liste des Partages.csv"
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "12") {
cls
Write-Host "** Exporter la liste des Imprimantes **"
Write-Host ""
Get-Printer | Select-Object Name, DriverName, PortName | Export-Csv -Path ".\Liste des imprimantes.csv" -NoTypeInformation
Write-Host ""
Write-Host "Resultat enregistre dans Liste des imprimantes.csv"
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "13") {
cls
Write-Host "** Exporter la liste des Parametres Reseaux **"
Write-Host ""
$NetworkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | where{$_.IPEnabled -eq "True"}
foreach ($Adapter in $NetworkAdapters)
{
   $IPAddress = $Adapter.IPAddress[0]
   $SubnetMask = $Adapter.IPSubnet[0]
   $DefaultGateway = $Adapter.DefaultIPGateway
   $DNS = $Adapter.DNSServerSearchOrder
   $Adapter.Description + " - " + $IPAddress + " - " + $SubnetMask + " - " + $DefaultGateway + " - " + $DNS | Out-File .\Parametres-Reseaux.txt -Append
}
ipconfig /all | Out-File -FilePath .\ipconfig.txt
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "14") {
cls
Write-Host "** Exporter la liste des GPO **"
Write-Host ""
param (
    [string]$ExportPath = "$env:USERPROFILE\GPOs"
)
if (!(Test-Path -Path $ExportPath -PathType Container)) {
    New-Item -ItemType Directory -Path $ExportPath
}
$GPOs = Get-GPO -All
foreach ($GPO in $GPOs) {
    $GPOName = $GPO.DisplayName
    $ExportFile = Join-Path -Path $ExportPath -ChildPath "$GPOName.xml"
    Write-Host "Export GPO '$GPOName' dans '$ExportFile' ..."
    Backup-GPO -Name $GPOName -Path $ExportFile -Comment "Exporte par un script PowerShell"
}
Write-Host "Toute les GPO ont ete exporte dans '$ExportPath'."
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "15") {
cls
Write-Host "** Exporter la liste des Groupes, Utilisateurs, Partages, Imprimantes, Parametres Reseaux et GPO **"
Write-Host ""
Import-Module ActiveDirectory
$outputFilePath = ".\Liste des groupes.txt"
$groups = Get-ADGroup -Filter *
$groups | Select-Object Name | Sort-Object Name | Out-File $outputFilePath
Write-Host ""
Write-Host "La liste des groupes a ete exporte vers $outputFilePath."
$OU=Read-Host "OU=Users,DC=domaine,DC=com"
#$OU = "OU=Users,DC=example,DC=com"
$Users = Get-ADUser -Filter * -SearchBase $OU
$Users | Select-Object Name, SamAccountName, EmailAddress | Export-CSV -Path ".\Liste des Utilisateurs.csv" -NoTypeInformation
$shares = Get-SmbShare
$shareList = @()
foreach ($share in $shares) {
    $shareList += [PSCustomObject]@{
        Name = $share.Name
        Path = $share.Path
        Description = $share.Description
        MaximumAllowed = $share.MaximumAllowed
        CachingMode = $share.CachingMode
        FolderEnumerationMode = $share.FolderEnumerationMode
    }
}
$shareList | Export-Csv -Path ".\Liste des Partages.csv" -NoTypeInformation
Get-Printer | Select-Object Name, DriverName, PortName | Export-Csv -Path ".\Liste des imprimantes.csv" -NoTypeInformation
$NetworkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | where{$_.IPEnabled -eq "True"}
foreach ($Adapter in $NetworkAdapters)
{
   $IPAddress = $Adapter.IPAddress[0]
   $SubnetMask = $Adapter.IPSubnet[0]
   $DefaultGateway = $Adapter.DefaultIPGateway
   $DNS = $Adapter.DNSServerSearchOrder
   $Adapter.Description + " - " + $IPAddress + " - " + $SubnetMask + " - " + $DefaultGateway + " - " + $DNS | Out-File .\Parametres-Reseaux.txt -Append
}
param (
    [string]$ExportPath = "$env:USERPROFILE\GPOs"
)
if (!(Test-Path -Path $ExportPath -PathType Container)) {
    New-Item -ItemType Directory -Path $ExportPath
}
$GPOs = Get-GPO -All
foreach ($GPO in $GPOs) {
    $GPOName = $GPO.DisplayName
    $ExportFile = Join-Path -Path $ExportPath -ChildPath "$GPOName.xml"
    Write-Host "Export GPO '$GPOName' dans '$ExportFile' ..."
    Backup-GPO -Name $GPOName -Path $ExportFile -Comment "Exporte par un script PowerShell"
}
Write-Host "Toute les GPO ont ete exporte dans '$ExportPath'."
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "16") {
cls
Write-Host "** Scanner le reseau local **"
Write-Host ""
Write-Host "Liste des adresses IP:"
(Get-NetIPAddress -AddressFamily IPV4).IPAddress
Write-Host ""
$subnet=Read-Host "xxx.xxx.xxx"
$range=1..255
$timeout= 1000
Write-Host ""
Write-Host "Scan en cours. Patientez."
Write-Host ""
foreach ($i in $range) {
    $ip = $subnet + "." + $i
    $result = Test-Connection -ComputerName $ip -Count 1 -ErrorAction SilentlyContinue -TimeToLive 5 -BufferSize 32
    if ($result) {
		$dnsName = [System.Net.Dns]::GetHostEntry($ip).HostName
        Write-Host "Hote $dnsname en $ip est en ligne."
    }
}
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "17") {
cls
Write-Host "** Activer les VSS **"
Write-Host ""
$vssStatus = Get-Service -Name "VSS" -ErrorAction SilentlyContinue
if ($vssStatus.Status -ne "Actif") {
    Start-Service -Name "VSS"
}
$volumesToEnable=Read-Host "Lecteur sous la forme C:\"
Enable-VVolumeShadowCopy -Volume $volumesToEnable
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "18") {
cls
Write-Host "** Reparation reseau **"
Write-Host ""
ipconfig /flushdns
arp * -d
ipconfig /release
ipconfig /renew
netsh winhttp reset proxy
netsh winhttp reset tracing
netsh winsock reset catalog
netsh int ipv4 reset catalog
netsh int ipv6 reset catalog
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "19") {
cls
Write-Host "** Reparation Windows Update **"
Write-Host ""
$arch = Get-WMIObject -Class Win32_Processor -ComputerName LocalHost | Select-Object AddressWidth 
Stop-Service -Name BITS 
Stop-Service -Name wuauserv 
Stop-Service -Name appidsvc 
Stop-Service -Name cryptsvc 
Remove-Item "$env:allusersprofile\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue 
Rename-Item $env:systemroot\SoftwareDistribution SoftwareDistribution.bak -ErrorAction SilentlyContinue 
Rename-Item $env:systemroot\System32\Catroot2 catroot2.bak -ErrorAction SilentlyContinue 
Remove-Item $env:systemroot\WindowsUpdate.log -ErrorAction SilentlyContinue 
Set-Location $env:systemroot\system32 
regsvr32.exe /s atl.dll 
regsvr32.exe /s urlmon.dll 
regsvr32.exe /s mshtml.dll 
regsvr32.exe /s shdocvw.dll 
regsvr32.exe /s browseui.dll 
regsvr32.exe /s jscript.dll 
regsvr32.exe /s vbscript.dll 
regsvr32.exe /s scrrun.dll 
regsvr32.exe /s msxml.dll 
regsvr32.exe /s msxml3.dll 
regsvr32.exe /s msxml6.dll 
regsvr32.exe /s actxprxy.dll 
regsvr32.exe /s softpub.dll 
regsvr32.exe /s wintrust.dll 
regsvr32.exe /s dssenh.dll 
regsvr32.exe /s rsaenh.dll 
regsvr32.exe /s gpkcsp.dll 
regsvr32.exe /s sccbase.dll 
regsvr32.exe /s slbcsp.dll 
regsvr32.exe /s cryptdlg.dll 
regsvr32.exe /s oleaut32.dll 
regsvr32.exe /s ole32.dll 
regsvr32.exe /s shell32.dll 
regsvr32.exe /s initpki.dll 
regsvr32.exe /s wuapi.dll 
regsvr32.exe /s wuaueng.dll 
regsvr32.exe /s wuaueng1.dll 
regsvr32.exe /s wucltui.dll 
regsvr32.exe /s wups.dll 
regsvr32.exe /s wups2.dll 
regsvr32.exe /s wuweb.dll 
regsvr32.exe /s qmgr.dll 
regsvr32.exe /s qmgrprxy.dll 
regsvr32.exe /s wucltux.dll 
regsvr32.exe /s muweb.dll 
regsvr32.exe /s wuwebv.dll 
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v AccountDomainSid /f 
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f 
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v SusClientId /f 
netsh winsock reset 
netsh winhttp reset proxy 
Get-BitsTransfer | Remove-BitsTransfer 
if($arch -eq 64){ 
    wusa Windows8-RT-KB2937636-x64 /quiet 
} 
else{ 
    wusa Windows8-RT-KB2937636-x86 /quiet 
} 
Start-Service -Name BITS 
Start-Service -Name wuauserv 
Start-Service -Name appidsvc 
Start-Service -Name cryptsvc 
wuauclt /resetauthorization /detectnow 
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "20") {
cls
Write-Host "** Reinitialisation mot de passe utilisateur **"
Write-Host ""
net user
Write-Host ""
$utilisateur=Read-Host "Utilisateur"
$motdepasse=Read-Host "Mot de passe"
net user '$utilisateur' '$motdepasse'
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "21") {
cls
Write-Host "** Informations systeme **"
Write-Host ""
$env:UserName
$Me = whoami.exe
$Admins = Get-LocalGroupMember -Name Administrateurs | 
       Select-Object -ExpandProperty name
if ($Admins -Contains $Me) {
      "Administrateur local"} 
    else {
     "Pas Administrateur local"}
Write-Host ""
$env:ComputerName
(Get-WmiObject -class Win32_OperatingSystem).Caption
Write-Host ""
systeminfo
Write-Host ""
wmic bios get serialnumber
Write-Host ""
systeminfo.exe | Out-File -FilePath .\informations-systeme.txt
Write-Host ""
Write-Host "Resultat enregistre dans informations-systeme.txt"
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "22") {
cls
Write-Host "** Afficher le mot de passe du Wifi **"
Write-Host ""
netsh wlan show profiles
$wifi=Read-Host "SSID"
netsh wlan show profile name=$wifi key=clear
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "23") {
cls
Write-Host "** Desactiver Bitlocker **"
Write-Host ""
$BLV = Get-BitLockerVolume
Disable-BitLocker -MountPoint $BLV
Get-BitlockerVolume -MountPoint $BLV
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "24") {
cls
Write-Host "** Verifier les ports ouverts **"
Write-Host ""
function Get-PortsWithProcess
{
  param([switch]$TCP,[switch]$UDP,[switch]$Listening)

  function Get-TCPPorts
  {
    $processes = Get-NetTCPConnection

    foreach ($process in $processes)
    {
      $process | Select -Property @{n="Proto";e={"TCP"}},LocalPort,LocalAddress,OwningProcess,@{n="ProcessName";e={(Get-Process -PID $process.OwningProcess).ProcessName}}
    }
  }
  function Get-TCPListener
  {
    $processes = Get-NetTCPConnection | ? {($_.State -eq "Listen") -and ($_.RemoteAddress -eq "0.0.0.0" -or "::")}

    foreach ($process in $processes)
    {
      $process | Select -Property @{n="Proto";e={"TCP"}},LocalPort,LocalAddress,OwningProcess,@{n="ProcessName";e={(Get-Process -PID $process.OwningProcess).ProcessName}}
    }
  }

  function Get-UDPPorts
  {
    $processes = Get-NetUDPEndpoint

    foreach ($process in $processes)
    {
      $process | Select -Property @{n="Proto";e={"UDP"}},LocalPort,LocalAddress,OwningProcess,@{n="ProcessName";e={(Get-Process -PID $process.OwningProcess).ProcessName}}
    }
  }
  if ($TCP) 
  { 
    Get-TCPListener | Format-Table
    Return
  }

  elseif ($TCP -and $Listening) 
  { 
    Get-TCPListener | Format-Table
    Return
  }

  elseif ($UDP) 
  { 
    Get-UDPPorts | Format-Table
    Return
  }

  elseif ( $TCP -eq $false -and $UDP -eq $false -and $Listening)
  {
    Get-TCPListener | Format-Table
    Get-UDPPorts | Format-Table
    Return
  }

  else
  {
    Get-TCPPorts | Format-Table
    Get-UDPPorts | Format-Table
    Return
  }
}
Get-PortsWithProcess
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "25") {
cls
Write-Host "** Nettoyage et optimisation Windows **"
Write-Host ""
$recycleBinShell = New-Object -ComObject Shell.Application
$recycleBinFolder = $recycleBinShell.Namespace(0xA)
$tempFilesENV = Get-ChildItem "env:\TEMP"
$tempFiles = $tempFilesENV.Value
$windowsTemp = "C:\Windows\Temp\*"
$winDist = "C:\Windows\SoftwareDistribution"
$recycleBinFolder.item() | %{Remove-Item $_.path -Recurse -Confirm:$false}
Remove-Item -Recure "$tempFiles\*"
Get-Service -Name WUAUSERV | Stop-Service
Remove-Item -Path $winDist -Recurse -Force
Get-Service -Name WUAUSERV | Start-Service
cleanmgr /sagerun:1 /VeryLowDisk /AUTOCLEAN | Out-Null
dism.exe /Online /Cleanup-Image /RestoreHealth
dism.exe /Online /Cleanup-Image /AnalyzeComponentStore
dism.exe /Online /Cleanup-Image /StartComponentCleanup
dism.exe /Online /Cleanup-Image /SPSuperseded
dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -PropertyType String -Value 'Off' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -PropertyType DWord -Value '0' -Force
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -PropertyType DWord -Value '0' -Force
$services = @(
    #'DiagTrack',
	#'XboxNetApiSvc'
)
foreach ($service in $services) {
    Set-Service $service -StartupType Disabled
}
powercfg -h off
$features = @(
    #'MediaPlayback',
	#'Internet-Explorer-Optional-amd64'
)
foreach ($feature in $features) {
    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
}
sfc /scannow
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "26") {
cls
Write-Host "** Exporter la liste des ordinateurs obsoletes **"
Write-Host ""
Import-Module ActiveDirectory
[int]$ComputerPasswordAgeDays = 90
$ComputerStaleDate = (Get-Date).AddDays(-$ComputerPasswordAgeDays)
$InactiveWorkstations = Get-ADComputer -filter { (passwordLastSet -le $ComputerStaleDate) -and (OperatingSystem -notlike "*Server*") -and (OperatingSystem -like "*Windows*") } -properties Name, DistinguishedName, OperatingSystem,OperatingSystemServicePack, passwordLastSet,LastLogonDate,Description
$InactiveWorkstations
$InactiveWorkstations | export-csv ".\ordinateurs-obsoletes.csv"
Write-Host ""
Write-Host "Resultat enregistre dans ordinateurs-obsoletes.csv"
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "27") {
cls
Write-Host "** Recherche des chemins long **"
Write-Host ""
$pathToScan = Read-Host "Repertoire racine"
$outputFilePath = ".\Longueur260.txt"
$maxcaratere = Read-Host "Nombre caratere maximum"
Write-Host ""
Write-Host "Analyse en cours. Patientez..."
Write-Host ""
$writeToConsoleAsWell = $true
$outputFileDirectory = Split-Path $outputFilePath -Parent
if (!(Test-Path $outputFileDirectory)) { New-Item $outputFileDirectory -ItemType Directory }
$stream = New-Object System.IO.StreamWriter($outputFilePath, $false)
Get-ChildItem -Path $pathToScan -Recurse -Force | Select-Object -Property FullName, @{Name="FullNameLength";Expression={($_.FullName.Length)}} | Sort-Object -Property FullNameLength -Descending | ForEach-Object {
    $filePath = $_.FullName
    $length = $_.FullNameLength
    $string = "$length : $filePath"
    if ($length -igt $maxcaratere) {if ($writeToConsoleAsWell) { Write-Host $string }}
    if ($length -igt $maxcaratere) {$stream.WriteLine($string)}
}
$stream.Close()
Write-Host ""
Write-Host "Resultat enregistre dans Longueur260.txt"
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause	
} elseif ($choice -eq "28") {
cls
Write-Host "** Activation Windows **"
Write-Host ""
$clewindows = Read-Host "Cle Windows (XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)"
dism /online /set-edition:ServerStandard /productKey:$clewindows /accepteula
Write-Host ""
Write-Host "Operation terminee."
pause
}elseif ($choice -eq "29") {
cls
Write-Host "** Liste des partages et droits **"
Write-Host ""
$shares = Get-SMBShare
Foreach($share in $shares){Get-SmbShareAccess -Name $share.Name | Out-File .\listepartagesetdroits.txt} 
Write-Host ""
Write-Host "Resultat enregistre dans listepartagesetdroits.txt"
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
Start-Process $scriptPath
}elseif ($choice -eq "30") {
cls
Write-Host "** Liste des partages et droits NTFS **"
Write-Host ""
# Fonction pour afficher les droits ACL
function Get-AclDetails {
    param (
        [string]$Path
    )
    
    $acl = Get-Acl -Path $Path
    $accessRules = $acl.Access | ForEach-Object {
        [PSCustomObject]@{
            Identity = $_.IdentityReference
            FileSystemRights = $_.FileSystemRights
            AccessControlType = $_.AccessControlType
        }
    }
    
    return $accessRules
}

# Obtenir la liste des partages
$shares = Get-WmiObject -Class Win32_Share

# Chemin du fichier de sortie
$outputFile = ".\listepartagesetdroitsntfs.txt"

# Parcourir chaque partage
foreach ($share in $shares) {
    Write-Host "Nom du partage : $($share.Name)"
    Write-Host "Chemin du partage : $($share.Path)"
    
    # Obtenez les droits ACL pour le partage
    $aclDetails = Get-AclDetails -Path $share.Path
    
    # Afficher les droits ACL
    Write-Host "Droits ACL :"
    $aclDetails | Format-Table -AutoSize
    
    # Obtenir les autorisations NTFS associées au partage
    $ntfsPermissions = Get-Item $share.Path | Get-Acl | Select-Object -ExpandProperty Access
    
    # Afficher les autorisations NTFS
    Write-Host "Autorisations NTFS :"
    $ntfsPermissions | Format-Table -AutoSize
    
    Write-Host "----------------------------------------------------"
    
    # Exporter les informations vers un fichier texte
    "Nom du partage : $($share.Name)" | Out-File -Append -FilePath $outputFile
    "Chemin du partage : $($share.Path)" | Out-File -Append -FilePath $outputFile
    "Droits ACL :" | Out-File -Append -FilePath $outputFile
    $aclDetails | Format-Table | Out-File -Append -FilePath $outputFile
    "Autorisations NTFS :" | Out-File -Append -FilePath $outputFile
    $ntfsPermissions | Format-Table | Out-File -Append -FilePath $outputFile
    "----------------------------------------------------" | Out-File -Append -FilePath $outputFile
}
Write-Host ""
Write-Host "Resultat enregistre dans listepartagesetdroitsntfs.txt"
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
} elseif ($choice -eq "31") {
cls
Write-Host "** Lister Groupes et membres des groupes d'un AD **"
Write-Host ""
# Spécifiez le nom du domaine Active Directory
$domainName=Read-Host "Nom de domaine (domaine.ext)"

# Chemin du fichier de sortie
$outputFile = ".\listegroupesmembres.txt"

# Créez une connexion à Active Directory
$ad = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$ad.Filter = "(&(objectCategory=group)(objectClass=group))"
$ad.PageSize = 1000
$ad.SearchScope = "Subtree"

# Parcourir les groupes dans Active Directory
$groups = $ad.FindAll()

foreach ($group in $groups) {
    $groupName = $group.Properties["sAMAccountName"][0]
    $groupMembers = $group.Properties["member"] | ForEach-Object {
        [ADSI]"LDAP://$_"
    } | ForEach-Object {
        $_.Properties["sAMAccountName"][0]
    }
    
    Write-Host "Nom du groupe : $groupName"
    Write-Host "Membres du groupe : $($groupMembers -join ', ')"
    Write-Host "----------------------------------------------------"
    
    # Exporter les informations vers le fichier texte
    "Nom du groupe : $groupName" | Out-File -Append -FilePath $outputFile
    "Membres du groupe : $($groupMembers -join ', ')" | Out-File -Append -FilePath $outputFile
    "----------------------------------------------------" | Out-File -Append -FilePath $outputFile
}
Write-Host ""
Write-Host "Resultat enregistre dans listegroupesmembres.txt"
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
}
elseif ($choice -eq "32") {
cls
Write-Host "** Maintenance sur le disque dur **"
Write-Host ""
$disk=Read-Host "Disque (exemple C:)"
Write-Host ""
Write-Host "Verification du disque en cours..."
Write-Host ""
chkdsk /f $disk
Write-Host ""
Write-Host "Nettoyage du disque en cours..."
Write-Host ""
cleanmgr.exe /d /autoclean /$disk
Write-Host ""
Write-Host "Defragmentation du disque en cours..."
Write-Host ""
defrag $disk
Write-Host ""
Write-Host "Operation terminee."
Write-Host ""
pause
}
elseif ($choice -eq "37") {
cls
Exit
}
