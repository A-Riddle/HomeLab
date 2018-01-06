#Adds DNS Servers after DCpromo wipes them, and creates a reverse DNS lookup Zone. Adds DNS Records to servers.
#Values to change
$dnsaddress = "127.0.0.1", "172.16.16.111", "8.8.8.8"
$Subnet_address = "172.16.16.0/24"
#Adds DNS A Records to DNS Server.
#Values to change
$Zone = "domain"
#Host1
$HName1 = "ESXi01"
$IPAddr1 = "172.16.16.31"
#Host2
$HName2 = "ESXi02"
$IPAddr2 = "172.16.16.32"
#Host3
$HName3 = "ESXi03"
$IPAddr3 = "172.16.16.33"
#Host4
$HName4 = "ESXi04"
$IPAddr4 = "172.16.16.34"
#Host5
$HName5 = "vCenter65"
$IPAddr5 = "172.16.16.112"

#After DC Promo
#Noticed that the DCPROMO wiped the previously set DNS servers.
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses $dnsaddress

#Create Reverse Lookup Zone
Add-DnsServerPrimaryZone -NetworkID $Subnet_address -ReplicationScope "Forest"

#Creates A and PTR Records on DNS servers.
add-DnsServerResourceRecordA -Name $HName1 -CreatePtr -IPv4Address $IPAddr1 -ZoneName $Zone
add-DnsServerResourceRecordA -Name $HName2 -CreatePtr -IPv4Address $IPAddr2 -ZoneName $Zone
add-DnsServerResourceRecordA -Name $HName3 -CreatePtr -IPv4Address $IPAddr3 -ZoneName $Zone
add-DnsServerResourceRecordA -Name $HName4 -CreatePtr -IPv4Address $IPAddr4 -ZoneName $Zone
add-DnsServerResourceRecordA -Name $HName5 -CreatePtr -IPv4Address $IPAddr5 -ZoneName $Zone


#Creates a Domain Admin & Standard Account on the domain. Copies groups from default Administrator account to new Domain Admin Account. Disables Administrator Account for security reasons.

#Values to change
#Domain Admin
$admin_password = ConvertTo-SecureString "Password" -AsPlainText -Force
$Admin_Username = "IT Admin"
$Admin_Given = "IT"
$Admin_Surname = "Admin"
$Admin_Logon_Name = "IT.Admin"
$Admin_OU_Path = "CN=Users,DC=AD,DC=Domain,DC=COM"
$Admin_Description = "Domain Admin, replaces basic Administrator Account"

#Standard Account
$standard_password = ConvertTo-SecureString "Password" -AsPlainText -Force
$Standard_Username = "Standard User"
$Standard_Given = "Standard"
$Standard_Surname = "User"
$Standard_Logon_Name = "Standard.User"
$Standard_OU_Path = "CN=Users,DC=AD,DC=Domain,DC=COM"
$Standard_Description = "Standard Domain User"

#Create Domain Admin
New-ADUser -Name $Admin_Username -AccountPassword $admin_password -Description $Admin_Description -ChangePasswordAtLogon $false -DisplayName $Admin_Username -Enabled $true -GivenName $Admin_Given -Surname $Admin_Surname -SamAccountName $Admin_Logon_Name -UserPrincipalName $Admin_Logon_Name -Path $Admin_OU_Path

#Copy Groups from Administrator to IT Admin
#http://www.sysadmins.eu/2015/02/copy-group-membership-to-another-user.html
get-aduser -identity Administrator -properties memberof | select memberof -expandproperty memberof | Add-ADGroupMember -members IT.Admin -PassThru

#Disable Administrator Account
Disable-ADAccount -Identity Administrator

#Create Domain Admin
New-ADUser -Name $Standard_Username -AccountPassword $standard_password -Description $Standard_Description -ChangePasswordAtLogon $false -DisplayName $Standard_Username -Enabled $true -GivenName $Standard_Given -Surname $Standard_Surname -SamAccountName $Standard_Logon_Name -UserPrincipalName $Standard_Logon_Name -Path $Standard_OU_Path
