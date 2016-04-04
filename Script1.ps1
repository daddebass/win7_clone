#imposto il colore per Script1.ps1, Bianco
[console]::ForegroundColor = "White"
$Host.UI.RawUI.WindowTitle = "Script1.ps1"

################################################
#----------------DICHIARAZIONE CARTELLE DI LAVORO, LOG, DIM. FINESTRA
[string]$data = Get-Date -UFormat "%d-%m-%y"
[string]$systemdrive = $env:SystemDrive
[string]$clonedir = "$PSScriptRoot\"
[string]$Logfile = "$clonedir\Script1_$data.log"
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Script1 Log---------------" | Out-File $LogFile -Append -Force
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] %systemdrive% coinvolta: $systemdrive" | Out-File $LogFile -Append -Force
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] cartella CLONE coinvolta: $clonedir" | Out-File $LogFile -Append -Force
#set-dimensioni finestra
$aff = (Get-Host).UI.RawUI
$bff = $aff.BufferSize
$bff.Width = 130
$bff.Height = 7000
$aff.BufferSize = $bff
$wff = $aff.WindowSize
$wff.Width = 130
$wff.Height = 60
$aff.WindowSize = $wff
#tramite WASP sposta la finestra in alto a sinistra
Select-Window Powershell | Set-WindowPosition -X 10 -Y 10
#imposto la finestra in primo piano
$signature=@'
	[DllImport("user32.dll")]
	public static extern bool SetWindowPos(
    IntPtr hWnd,
    IntPtr hWndInsertAfter,
    int X,
    int Y,
    int cx,
    int cy,
    uint uFlags);
'@
$type = Add-Type -MemberDefinition $signature -Name SetWindowPosition -Namespace SetWindowPos -Using System.Text -PassThru
$handle = (Get-Process -id $Global:PID).MainWindowHandle 
$alwaysOnTop = New-Object -TypeName System.IntPtr -ArgumentList (-1) 
$type::SetWindowPos($handle, $alwaysOnTop, 0, 0, 0, 0, 0x0003) | Out-Null

################################################
#----------------PULIZIA SCHERMO, STOP AL SERVIZIO FIREWALL E DISABILITA AUTOLOGON Script1
Clear
#attendo che il servizio WinRM sia acceso per proseguire con lo script
Write-Host "Attendi...  " -NoNewLine
$anim=@("|","/","-","\","|")
while((Get-Wmiobject -Class "Win32_Service" -Filter "Name='WinRM'").State -NE "Running"){
	$anim | %{Write-Host "`b$_" -NoNewLine;Start-Sleep -m 500}
}
if((Get-Wmiobject -Class "Win32_Service" -Filter "Name='WinRM'").State -EQ "Running"){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] WinRM partito" | Out-File $LogFile -Append -Force
}
Write-Host "`n"
Write-Host "* DISABILITO TMG FOREFRONT PER NON AVERE PROBLEMI"
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] FwcAgent: $((Stop-Service FwcAgent -WarningAction SilentlyContinue -PassThru).Status)" | Out-File $LogFile -Append -Force
Write-Host "`n* DISABILITO L'AUTOLOGON DI Script1.ps1 ABILITANDO Script2.ps1" 
Remove-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Script1_Start
if((Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Script1_Start -ErrorAction SilentlyContinue) -EQ $null){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Script1 rimosso da HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File $LogFile -Append -Force
}
elseif(Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Script1_Start -ErrorAction SilentlyContinue){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Script1 NON rimosso da HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File $LogFile -Append -Force
	Write-Host "* Script1 NON rimosso da HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ForegroundColor red
	Sleep 5
	Exit
}
if(New-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name Script2_Start -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File $clonedir\Script2.ps1"){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Script2 inserito in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File $LogFile -Append -Force
}
elseif((Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Script2_Start -ErrorAction SilentlyContinue) -EQ $null){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Script2 NON inserito in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File $LogFile -Append -Force
	Write-Host "* Script2 NON inserito da HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ForegroundColor red
	Sleep 5
	Exit
}

################################################
#----------------SET SCHEDA DI RETE & SET HOSTNAME
Write-Host "`n* RICAVO IL MAC-ADDRESS DELLA SCHEDA DI RETE, LO USO COME INDICE PER IMPOSTARE I DATI DI RETE E IL NOMEHOST" 
[string]$mac = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE AND NOT Description LIKE 'VMWare%'").MACAddress
Write-Host "* Mac-Address --> $mac"
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Mac Address: $mac" | Out-File $LogFile -Append -Force
#se non trovo corrispondenze nel file $clonedir\mac_ip_nome.inf richiedo i dati manualmente
if((Select-String -Path $clonedir\mac_ip_nome.inf -Pattern $mac | ForEach-Object {$_.Line}) -EQ $null){
	do{
		[console]::ForegroundColor = "Magenta"
		[string]$NewHn = Read-Host "* NON HO TROVATO CORRISPONDENZE IN $clonedir\MAC_IP_NOME.INF. INSERISCI MANUALMENTE L'HOSTNAME"
		[string]$Ip = Read-Host "* ....E L'IP"
		#-- 0. PARTE DA DE-COMMENTARE (DA LINEA 95 A 108) SE SI PREPARA UN NUOVO LABORATORIO, IN MODO TALE DA RICHIEDERE SOLO L'id DELLA POSTAZIONE SENZA INSERIRE ANCHE L'IP
		#-- 1. COMPILA L'OFFSET_HOSTNAME, L'OFFSET_IP & L'IP DELLA TUTOR
		#-- 2. COMMENTA LE RIGHE 89 & 90 (QUELLE IMMEDIATAMENTE SOPRA A QUESTE)
		#-- 3. COMMENTA LA RIGA 111, IN MODO TALE DA INIBIRE, IN SCRIPT2.ps1, L'INVIO DELLA MAIL SE POSTAZIONE NON TROVATA IN mac_ip_nome.inf
		<#
		[string]$offset_HOSTNAME = "LAB14A1"
		[string]$offset_IP = "10.114.2."
		[string]$id_PC = Read-Host "POSTAZIONE? (TUTOR,1,2,3...)"
		if($id_PC -EQ "TUTOR"){
			[string]$NewHn = $offset_HOSTNAME + $id_PC
			[string]$ip = "10.114.2.239"
		}
		else{
			[string]$NewHn = $offset_HOSTNAME + "P" + $id_PC
			[string]$ip_ultimo_ottetto = 20 + $id_PC
			[string]$ip = $offset_IP + $ip_ultimo_ottetto
		}
		#>
		[string]$conferma = Read-Host "* TUTTO OK? s/n"
	}until($conferma -EQ "s")
	($mac + "=" + $ip + "=" + $NewHn) | Out-File $clonedir\"recovery_"$NewHn"_mac_ip_nome.inf"
	Write-Host "`n"
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] POSTAZIONE NON TROVATA IN $clonedir\mac_ip_nome.inf" | Out-File $LogFile -Append -Force
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Stringa per mac_ip_nome.inf: $($mac + "=" + $ip + "=" + $NewHn)" | Out-File $LogFile -Append -Force
	[console]::ResetColor()
	[console]::ForegroundColor = "White"
}
#altrimenti proseguo normalmente
else{
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] stringa da mac_ip_nome.inf: $(Select-String -Path $clonedir\mac_ip_nome.inf -Pattern $mac | ForEach-Object {$_.Line})" | Out-File $LogFile -Append -Force
	[string]$NewHn = (Select-String -Path $clonedir\mac_ip_nome.inf -Pattern $mac | ForEach-Object {$_.Line}).Split("=")[2]
	[string]$Ip = (Select-String -Path $clonedir\mac_ip_nome.inf -Pattern $mac | ForEach-Object {$_.Line}).Split("=")[1]
}
[string]$Gw = $Ip.Remove(7) + "0.1"
switch($Ip.Remove(6)){
	#per i dns mi baso sulla subnet
	{($_ -EQ "10.101") -OR ($_ -EQ "10.103") -OR ($_ -EQ "10.105") -OR $_ -EQ ("10.109")}{[array]$dns = "10.109.8.17","10.109.8.18","10.107.8.17","10.107.8.18"}
	{($_ -EQ "10.107") -OR ($_ -EQ "10.114") -OR ($_ -EQ "10.188")}{[array]$dns = "10.107.8.17","10.107.8.18","10.109.8.18","10.109.8.17"}
	{($_ -EQ "10.108")}{[array]$dns = "10.108.1.247","10.107.8.17","10.107.8.18","10.109.8.17"}
	{($_ -EQ "10.116")}{[array]$dns = "10.116.1.254","10.107.8.17","10.107.8.18","10.109.8.17"}
	{($_ -EQ "10.146")}{[array]$dns = "10.107.8.17","10.107.8.18","10.109.8.17","10.109.8.18"}
}
Write-Host "* HostName: $NewHn"
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] HostName: $NewHn" | Out-File $LogFile -Append -Force
#imposto la scheda di rete con indirizzamento statico, ricavando l'indice della scheda di nrete
[string]$index = (Get-WmiObject Win32_NetworkAdapter | Where {$_.MACAddress -EQ $mac}).InterfaceIndex
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] NIC Index: $index" | Out-File $LogFile -Append -Force
#Ip
Write-Host "* Ip: $Ip"
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] IP: $Ip" | Out-File $LogFile -Append -Force
if(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).EnableStatic($Ip, "255.255.248.0")).ReturnValue -EQ 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Indirizzo IP impostato correttamente" | Out-File $LogFile -Append -Force
}
elseif(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).EnableStatic($Ip, "255.255.248.0")).ReturnValue -NE 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] IP NON impostato. Codice errore: $(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).EnableStatic($ip, "255.255.248.0")).ReturnValue)" | Out-File $LogFile -Append -Force
	"info: https://msdn.microsoft.com/en-us/library/windows/desktop/aa394217(v=vs.85).aspx" | Out-File $LogFile -Append -Force
	Write-Host "* IP NON impostato. Codice errore: $(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).EnableStatic($ip, "255.255.248.0")).ReturnValue)" -ForegroundColor red
	Sleep 5
	Exit
}
#Gateway
Write-Host "* Gateway: $Gw"
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Gateway: $Gw" | Out-File $LogFile -Append -Force
if(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetGateways($Gw)).ReturnValue -EQ 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Gateway impostato correttamente" | Out-File $LogFile -Append -Force
}
elseif(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetGateways($Gw)).ReturnValue -NE 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Gateway NON impostato. Codice errore: $((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetGateways($Gw).ReturnValue)" | Out-File $LogFile -Append -Force
	"info: https://msdn.microsoft.com/en-us/library/windows/desktop/aa394217(v=vs.85).aspx" | Out-File $LogFile -Append -Force
	Write-Host "* Gateway NON impostato. Codice errore: $((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetGateways($Gw).ReturnValue)" -ForegroundColor red
	Sleep 5
	Exit
}
#Dns
Write-Host "* Dns: $dns"
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DNS: $dns" | Out-File $LogFile -Append -Force
if(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetDNSServerSearchOrder($dns)).ReturnValue -EQ 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DNS impostati correttamente" | Out-File $LogFile -Append -Force
	if(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetDynamicDNSRegistration("TRUE")).ReturnValue -EQ 0){
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DynamicDNSRegistration ok" | Out-File $LogFile -Append -Force
	}
}
elseif(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetDNSServerSearchOrder($dns)).ReturnValue -NE 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DNS NON impostati. Codice errore: $(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetDNSServerSearchOrder($dns)).ReturnValue)" | Out-File $LogFile -Append -Force
	"info: https://msdn.microsoft.com/en-us/library/windows/desktop/aa394217(v=vs.85).aspx" | Out-File $LogFile -Append -Force
	Write-Host "* DNS NON impostati. Codice errore: $(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetDNSServerSearchOrder($dns)).ReturnValue)" -ForegroundColor red
	Sleep 5
	Exit
}
#aspetto la connettivita verso i dns per poi procedere
do{
	Start-Sleep 2
	$ping = Test-Connection -ComputerName $dns[0] -Count 1 -Quiet -ErrorAction SilentlyContinue
}until($ping -EQ "True")
if($ping -EQ "True"){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Connettivita verso i DNS ok" | Out-File $LogFile -Append -Force
}
elseif($ping -NE "True"){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Connettivita verso i DNS assente" | Out-File $LogFile -Append -Force
	Write-Host "* Connettivita verso i DNS assente" -ForegroundColor red
	Sleep 5
	Exit
}
#rename solo se il nome è cambiato
[string]$OldHn = $env:ComputerName
if($OldHn -NE $NewHn){
	Write-Host "`n* RENAME..."
	Rename-Computer -NewName $NewHn
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Rename in $NewHn" | Out-File $LogFile -Append -Force
}
elseif($OldHn -EQ $NewHn){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] No rename: master/medesima postazione" | Out-File $LogFile -Append -Force
}


################################################
#----------------RIPRISTINO BOOT DOPO WOL DA HD
if(((gwmi -Class:Win32_ComputerSystem).Manufacturer) -EQ "Hewlett-Packard"){
	if((gwmi -Namespace root/hp/instrumentedBIOS -Class hp_biosEnumeration | where Name -EQ "Remote Wakeup Boot Source").CurrentValue -EQ "Remote Server"){
		Write-Host "`n* $((Get-WmiObject -Class:Win32_ComputerSystem).Model): Re-imposto il boot dopo WOL  su Local Hard Drive"
		#per HP agisco con root\hp\instrumentedbios
		if(((gwmi -Class hp_biossettinginterface -Namespace root\hp\instrumentedbios).SetBIOSSetting("Remote Wakeup Boot Source","Local Hard Drive")).Return -EQ 0){
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] $((Get-WmiObject -Class:Win32_ComputerSystem).Model): Boot dopo WOL re-impostato su Local Hard Drive" | Out-File $LogFile -Append -Force
		}
		elseif(((gwmi -Class hp_biossettinginterface -Namespace root\hp\instrumentedbios).SetBIOSSetting("Remote Wakeup Boot Source","Local Hard Drive")).Return -NE 0){
			Write-Host "`n* $((Get-WmiObject -Class:Win32_ComputerSystem).Model): Boot dopo WOL NON re-impostato su Local Hard Drive"
			Sleep 10
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] $((Get-WmiObject -Class:Win32_ComputerSystem).Model): Boot dopo WOL NON re-impostato su Local Hard Drive" | Out-File $LogFile -Append -Force
		}
	}
}
if(((gwmi -Class:Win32_ComputerSystem).Manufacturer) -EQ "LENOVO"){
	[string]$1st_AutomaticBootSequence = ((gwmi -class Lenovo_BiosSetting -namespace root\wmi | Where-Object {$_.CurrentSetting.split(",",[StringSplitOptions]::RemoveEmptyEntries) -EQ "Automatic Boot Sequence"}).CurrentSetting).Split(",")[1].Split(":")[0]
	if($1st_AutomaticBootSequence -EQ "Network 1"){
		Write-Host "`n* LENOVO $((Get-WmiObject -Class:Win32_ComputerSystem).Model): Re-imposto il boot dopo WOL  su Local Hard Drive"
		#per Lenovo agisco con Lenovo_SetBiosSetting
		if(((gwmi -class Lenovo_SetBiosSetting –Namespace root\wmi).SetBIOSSetting("Automatic Boot Sequence,SATA 1:Network 1:SATA 2:SATA 3:eSATA:Other Device;[Excluded from boot order:USB FDD:USB HDD:USB CDROM:USB KEY]")).Return -EQ "Success"){
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] LENOVO $((Get-WmiObject -Class:Win32_ComputerSystem).Model): Boot dopo WOL re-impostato su SATA 1" | Out-File $LogFile -Append -Force
		}
		elseif(((gwmi -class Lenovo_SetBiosSetting –Namespace root\wmi).SetBIOSSetting("Automatic Boot Sequence,SATA 1:Network 1:SATA 2:SATA 3:eSATA:Other Device;[Excluded from boot order:USB FDD:USB HDD:USB CDROM:USB KEY]")).Return -NE "Success"){
			Write-Host "`n* $((Get-WmiObject -Class:Win32_ComputerSystem).Model): Boot dopo WOL NON re-impostato su Local Hard Drive"
			Sleep 10
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] $((Get-WmiObject -Class:Win32_ComputerSystem).Model): Boot dopo WOL NON re-impostato su Local Hard Drive" | Out-File $LogFile -Append -Force
		}
	}
}

################################################
#----------------AGGIORNO BGINFO & RIAVVIO
Write-Host "`n* FACCIO GIRARE BGINFO E RIAVVIO`n"
if(Start-Process C:\Windows\System32\Bginfo.exe -ArgumentList 'C:\bginfo.bgi /timer:0 /NOLICPROMPT /silent' -PassThru){
	Wait-Process -Id (Get-Process Bginfo).Id
	Copy-Item C:\temp\backgroundDefault.jpg C:\Windows\System32\oobe\info\backgrounds
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Bginfo aggiornato" | Out-File $LogFile -Append -Force
}
Start-Sleep 3
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Script1 Log terminato " | Out-File $LogFile -Append -Force
Restart-Computer