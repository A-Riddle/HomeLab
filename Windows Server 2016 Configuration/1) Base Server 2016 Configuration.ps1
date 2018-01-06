#Renames computer, configure networking, enable RDP w/NLA, sets power options, disables Defrag, disables services, removes Windows Defender.

#Values to change
$Hostname= "DC01"
$ipaddress = "172.16.16.110"
$dnsaddress = "127.0.0.1","172.16.16.111","8.8.8.8"
$gateway = "172.16.16.1"

#Rename Computer
Rename-Computer -NewName $Hostname

#Configure Networking
New-NetIPAddress -InterfaceAlias Ethernet -IPAddress $ipaddress -AddressFamily IPv4 -PrefixLength 24 -defaultgateway $gateway
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $dnsaddress

#Enable RDP
#http://tomaskalabis.com/wordpress/enabledisable-rdp-using-powershell/
$RDPEnable = 1
$RDPFirewallOpen = 1
$NLAEnable = 1

# Enable Remote Desktop Connections
$RDP = Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices -Authentication PacketPrivacy
$Result = $RDP.SetAllowTSConnections($RDPEnable,$RDPFirewallOpen)

if ($Result.ReturnValue -eq 0)
{
    Write-Host "Remote Connection settings changed sucessfully" -ForegroundColor Cyan
}
else
{
    Write-Host ("Failed to change Remote Connections setting(s), return code "+$Result.ReturnValue) -ForegroundColor Red
    exit
}

# Set Network Level Authentication level
$NLA = Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\CIMV2\TerminalServices -Authentication PacketPrivacy
$NLA.SetUserAuthenticationRequired($NLAEnable) | Out-Null
$NLA = Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\CIMV2\TerminalServices -Authentication PacketPrivacy
if ($NLA.UserAuthenticationRequired -eq $NLAEnable)
{
    Write-Host "NLA setting changed sucessfully" -ForegroundColor Cyan
}
else
{
    Write-Host "Failed to change NLA setting" -ForegroundColor Red
    exit
}

#Set Power Plan to High
#https://facility9.com/2015/07/controlling-the-windows-power-plan-with-powershell/
Try {
        $HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
        $CurrPlan = $(powercfg -getactivescheme).split()[3]
        if ($CurrPlan -ne $HighPerf) {powercfg -setactive $HighPerf}
    } Catch {
        Write-Warning -Message "Unable to set power plan to high performance"
    }

#Disable Defrag
#http://www.purepowershellguy.com/?p=12471
If ((Get-ScheduledTask -TaskName 'ScheduledDefrag').State -eq 'Ready')
{
    Disable-ScheduledTask -TaskName 'ScheduledDefrag' -TaskPath '\Microsoft\Windows\Defrag'
}
Get-ScheduledTask -TaskName 'ScheduledDefrag'

#Disable Services
Get-Service MapsBroker,TapiSrv,WalletService,XblAuthManager,bthserv,lfsvc,FrameServer,icssvc,XblGameSave,WSearch | Set-Service -StartupType disabled | Set-Service -Status Stopped

#Uninstall Feature
Remove-WindowsFeature  Windows-Defender-Features

#Change Windows Update Settings to Automatic
#https://social.technet.microsoft.com/Forums/office/en-US/005f4664-8e49-4331-86bd-341e24b9948f/powershell-script-to-change-windows-automatic-update-settings?forum=winserverpowershell
$WUSettings = (New-Object -com "Microsoft.Update.AutoUpdate").Settings
$WUSettings.NotificationLevel=4
$WUSettings.save()

#Automatic Updates for all Microsoft Products
#https://morgansimonsen.com/2013/01/15/how-to-opt-in-to-microsoft-update-with-powershell/
$mu = New-Object -ComObject Microsoft.Update.ServiceManager -Strict
$mu.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")

#Enable Smart Screen
#https://gist.github.com/alirobe/7f3b34ad89a159e6daa1#file-reclaimwindows10-ps1
#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "RequireAdmin"
#Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation"

#Disable Telemetry
#https://gist.github.com/alirobe/7f3b34ad89a159e6daa1#file-reclaimwindows10-ps1
Write-Host "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

#Reboots Computer to apply changes
Restart-Computer

