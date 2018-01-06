#Values to Change
$featureLogPath = “c:\featurelog.txt”
$Domain = "AD.Domain.com"
$secure_password = ConvertTo-SecureString "Password" -AsPlainText -Force
$Database_path = "C:\Windows\NTDS"
$Netbios_Name = "Domain"
$Log_Path = "C:\Windows\NTDS"
$Sysvol_Path = "C:\Windows\SYSVOL"
$Forest_Domain_Level = "WinThreshold"

#Install AD DS, DNS and GPMC  
start-job -Name addFeature -ScriptBlock { 
    Add-WindowsFeature -Name “ad-domain-services”  -IncludeManagementTools 
    Add-WindowsFeature -Name “dns” -IncludeManagementTools 
    Add-WindowsFeature -Name “gpmc” -IncludeManagementTools } 
Wait-Job -Name addFeature 
Get-WindowsFeature | Where installed >>$featureLogPath

#Install DC
Import-Module ADDSDeployment
Install-ADDSDomainController `
    -DomainName $Domain `
    -SafeModeAdministratorPassword $secure_password `
    -CreateDnsDelegation:$false `
    -DatabasePath $Database_path `
    -DomainMode $Forest_Domain_Level `
    -DomainNetbiosName $Netbios_Name `
    -ForestMode $Forest_Domain_Level `
    -InstallDns:$true `
    -LogPath $Log_Path `
    -SysvolPath $Sysvol_Path `
    -Force:$true
