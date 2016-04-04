#Imposto il colore per PreClone.ps1, Ciano.
[console]::ForegroundColor = "Cyan"
$Host.UI.RawUI.WindowTitle = "_PreClone.ps1"

################################################
#----------------DICHIARAZIONE CARTELLE DI LAVORO, LOG, DIM. FINESTRA
[string]$Data = Get-Date -UFormat "%d-%m-%y"
[string]$SystemDrive = $env:SystemDrive
[string]$CloneDir = "$PSScriptRoot\"
[string]$LogFile = "$clonedir\_PreClone_$data.log"
#rimozione vecchi logs
if(Test-Path $clonedir\*.log){
	Remove-Item $clonedir\*.log
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Vecchi log rimossi" | Out-File $LogFile -Append -Force
}
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] _PreClone Log---------------" | Out-File $LogFile -Append -Force
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
#----------------CONTROLLI PRELIMINARI SE ADMIN E SE \\lib\shareddata\ E' DISPONIBILE E SE PS ALMENO >/= 4
if(!(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))){
	Write-Host "* DEVI ESERE AMMINISTRATORE PER FAR GIRARE PreClone.ps1!" -ForegroundColor "red"
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] No Amministratore: esco dallo script" | Out-File $LogFile -Append -Force
	Sleep 5
	Exit
}
if(!(Test-Path \\lib\shareddata\lib\client\mac_ip_nome.inf)){
	Write-Host "* \\lib\shareddata\ OFFLINE O mac_ip_nome.inf NON DISPONIBILE" -ForegroundColor "red"
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] \\lib\shareddata\ OFFLINE O mac_ip_nome.inf NON DISPONIBILE" | Out-File $LogFile -Append -Force
	Sleep 5
	Exit
}
if(!(((Get-Host).Version).Major -GE 4)){
	Write-Host "* Versione di PowerShell non compatibile con questa CLONE" -ForegroundColor "red"
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] CLONE compatibile con PowerShell 4 o superiore" | Out-File $LogFile -Append -Force
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Versione di PowerShell su questo client: $(((Get-Host).Version).Major)" | Out-File $LogFile -Append -Force
	Sleep 5
	Exit
}


################################################
#----------------LETTURA CREDENZIALI DI ADMIN, JOINER E INSTALLER & ELIMINO I VECCHI LOGS
#chiudo le finestre attive
(Get-Process | Where-Object {($_.MainWindowHandle -NE 0) -AND ($_.Name -NE 'powershell') -AND ($_.Name -NE 'explorer')}) | Stop-Process
Write-Host "`n* LETTURA CREDENZIALI NECESSARIE IN POST-CLONAZIONE (LOCALHOST\ADMINISTRATOR, lib\joiner, lib\installer)" 
do{
	do{
		#acquisisco le pw in formato sicuro...
		[console]::ForegroundColor = "DarkCyan" 
		$psw_admin_secure = Read-Host -AsSecureString "* Password di ADMINISTRATOR"
		$psw_joiner_secure = Read-Host -AsSecureString "* Password di lib\joiner"
		$psw_installer_secure = Read-Host -AsSecureString "* Password di lib\installer"
		[string]$psw_admin = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($psw_admin_secure))
		[string]$psw_joiner = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($psw_joiner_secure))
		[string]$psw_installer = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($psw_installer_secure))
		#...per poi de-criptarle per una verifica dela veridicità
		$CurrentDomain = "LDAP://" + ([ADSI]"").DistinguishedName
		$ver_joiner = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,"joiner",$psw_joiner)
		$ver_installer = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,"installer",$psw_installer)
		#verifico aggiungendo la classe .NET necessaria
		Add-Type -Assemblyname System.DirectoryServices.Accountmanagement
		#dichiaro l'oggetto local account management
		$LAM = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
		$ver_administrator = $LAM.ValidateCredentials("Administrator", $psw_admin)
		if(($ver_joiner.Name -EQ $null) -OR ($ver_installer.Name -EQ $null) -OR ($ver_administrator -ne $true)){
			Write-Host "`n* UNA O PIU PW ERRATE: RE-INSERIRE..."
			Sleep 1
		}
	}until(($ver_joiner.Name -ne $null) -AND ($ver_installer.Name -ne $null) -AND ($ver_administrator -EQ $true))
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Credenziali di Administrator, Joiner, Installer acquisite e verificate" | Out-File $LogFile -Append -Force
	[string]$conferma = Read-Host "* CREDENZIALI CORRETTE: CONTINUO? s/n"
}until($conferma -EQ "s")
#acquisisco la versione della master
[string]$ver_master = (Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM" -Name "VERSIONE_MASTER").VERSIONE_MASTER
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Versione Master (old value): $ver_master" | Out-File $LogFile -Append -Force
do{
	#propongo il valore di default di $ver_master da editare
	[void][System.Windows.Forms.SendKeys]
	[System.Windows.Forms.SendKeys]::SendWait(([regex]'([\{\}\[\]\(\)\+\^\%\~])').Replace($ver_master, '{$1}'))
	[string]$ver_master = Read-Host -Prompt "* Revisione della master [INVIO per accettare il default o modifica il valore proposto]"
	trap{
		[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
		Continue
	}
	[string]$conferma = Read-Host "* Sicuro? s/n"	
}until($conferma -EQ "s")
#compilo il registro con le informazioni della versione master e la data di acquisizione immagine
[string]$data_ora_master = Get-Date -format d/M/yyyy" "-" "%H:mm
Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM" -Name "VERSIONE_MASTER" -value $ver_master
Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM" -Name "DATA_MASTER" -value $data_ora_master
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Versione Master: $ver_master (new value)" | Out-File $LogFile -Append -Force
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Data/Ora acquisizione img: $data_ora_master" | Out-File $LogFile -Append -Force
[console]::ResetColor()
[console]::ForegroundColor = "cyan"

################################################
#----------------STOP INTERFACCE VIRTUALI VMWARE/TMG FOREFRONT
Write-Host "`n* DISABILITO LE INTERFACCE VIRTUALI DI VMWARE PLAYER - se presenti..." 
if((Get-WmiObject Win32_NetworkAdapter | Where {$_.ServiceName -EQ "VMnetAdapter"}).InterfaceIndex){
	devcon.exe disable *VMnetAdapter* | Out-Null
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Interfacce VMWARE disabilitate" | Out-File $LogFile -Append -Force
}
Write-Host "`n* DISABILITO IL SERVIZIO DI FIREWALL TMG FOREFRONT PER NON AVERE PROBLEMI..." 
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] FwcAgent: $((Stop-Service FwcAgent -WarningAction SilentlyContinue -PassThru).Status)" | Out-File $LogFile -Append -Force

################################################
#----------------SVUOTA TMP, CESTINO, RIMUOVO LOGON SCRIPT DA STARTUP & COPIA MAC_IP_NOME.INF
#avvio il job di repulisti
Write-Host "`n* PULIZIA temp & cestino..."
$RepulistiJob = Start-Job -ScriptBlock {
	Remove-Item $env:temp\*.* -Force -Recurse -ErrorAction:SilentlyContinue
	$Recycler = (New-Object -ComObject Shell.Application).NameSpace(0xa)
	$Recycler.items() | foreach {rm $_.path -Force -Recurse }
}
Wait-Job $RepulistiJob | Out-Null
if($RepulistiJob.State -EQ 'Completed'){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Cestino e tmp svuotate" | Out-File $LogFile -Append -Force
}
if(Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\LOGON_SCRIPT.lnk"){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] LINK A C:\LOGON_SCRIPT.ps1 rimosso DA C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" | Out-File $LogFile -Append -Force
}
else{
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] LINK A C:\LOGON_SCRIPT.ps1 NON RIMOSSO DA C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" | Out-File $LogFile -Append -Force
}
Write-Host "`n* STO COPIANDO IL FILE MAC_IP_NOME.INF DA \\LIB\SHAREDDATA\LIB\CLIENT" 
if(Copy-Item \\lib\shareddata\lib\client\mac_ip_nome.inf $clonedir){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] mac_ip_nome.inf copiato da \\lib\shareddata\lib\client\" | Out-File $LogFile -Append -Force
}

################################################
#----------------UNJOIN & IMPOSTAZIONE SCHEDA DI RETE PER FUNZIONAMENTO DHCP
Write-Host "`n* STO RIMUOVENDO IL PC DAL DOMINIO, UTILIZZANDO LIB\JOINER..." 
$Credential_Joiner = New-Object System.Management.Automation.PSCredential("lib.unimib.it\joiner",($psw_joiner | ConvertTo-SecureString -AsPlainText -Force))
if($Credential_Joiner){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Credenziali per lib\joiner generate" | Out-File $LogFile -Append -Force
	$Remove_Result = (Remove-Computer -UnjoinDomaincredential $Credential_Joiner -Force -Verbose -PassThru).HasSucceeded
	if($Remove_Result -EQ "True"){
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] $($env:ComputerName) rimossa dal dominio" | Out-File $LogFile -Append -Force
	}
	elseif($Remove_Result -NE "True"){
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] $($env:ComputerName) NON rimossa dal dominio" | Out-File $LogFile -Append -Force
		Write-Host "* $($env:ComputerName) NON rimossa dal dominio" -ForegroundColor red
		Sleep 5
		Exit
	}
}
elseif(!($Credential)){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Credenziali per lib\joiner NON generate" | Out-File $LogFile -Append -Force
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] $($env:ComputerName) NON rimossa dal dominio" | Out-File $LogFile -Append -Force
	Write-Host "* $($env:ComputerName) NON rimossa dal dominio!" -ForegroundColor "red"
	Sleep 5
	Exit
}
[string]$mac = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE AND NOT Description LIKE 'VMWare%'").MACAddress
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Mac Address: $mac" | Out-File $LogFile -Append -Force
Write-Host "`n* CONFIGURAZIONE DELLA SCHEDA DI RETE: ABILITO L'ASSEGNAMENTO DINAMICO DELL'IP. POTREBBERO ESSERE NECESSARI ALCUNI SECONDI.." 
[string]$index = (Get-WmiObject Win32_NetworkAdapter | Where {$_.MACAddress -EQ $mac}).InterfaceIndex
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] NIC Index: $index" | Out-File $LogFile -Append -Force
if(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).EnableDHCP()).ReturnValue -EQ 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Rete su DHCP impostata correttamente" | Out-File $LogFile -Append -Force
}
elseif(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).EnableDHCP()).ReturnValue -NE 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Rete su DHCP NON IMPOSTATA correttamente. Codice errore: $(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).EnableDHCP()).ReturnValue)" | Out-File $LogFile -Append -Force
	"info: https://msdn.microsoft.com/en-us/library/windows/desktop/aa394217(v=vs.85).aspx" | Out-File $LogFile -Append -Force
	Write-Host "* Rete su DHCP NON IMPOSTATA correttamente. Codice errore: $(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).EnableDHCP()).ReturnValue)" -ForegroundColor "red"
	Sleep 5
	Exit
}
if(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetDNSServerSearchOrder()).ReturnValue -EQ 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DNS re-impostati correttamente" | Out-File $LogFile -Append -Force
}
elseif(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetDNSServerSearchOrder()).ReturnValue -NE 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DNS NON re-impostati correttamente. Codice errore: $(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetDNSServerSearchOrder()).ReturnValue)" | Out-File $LogFile -Append -Force
	"info: https://msdn.microsoft.com/en-us/library/windows/desktop/aa394217(v=vs.85).aspx" | Out-File $LogFile -Append -Force
	Write-Host "* DNS NON re-impostati correttamente. Codice errore: $(((Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ $index}).SetDNSServerSearchOrder()).ReturnValue)" -ForegroundColor "red"
	Sleep 5
	Exit
}

################################################
#----------------CRIPTO LE PW, GENERANDO UNA CHIAVE DI DE-CRYPT CASUALE
Write-Host "`n* STO CRIPTANDO LE PASSWORD DI LIB\installer E DI LIB\joiner..."
#chiavi casuali in due files in $clonedir
[array]$key1 = (1..24 | % {(Get-Random -Minimum 1 -Maximum 200)})
$key1 | Out-File $clonedir\secure1.key
if(Test-Path $clonedir\secure1.key){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure1.key generata" | Out-File $LogFile -Append -Force
}
elseif(!(Test-Path $clonedir\secure1.key)){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure1.key NON GENERATA" | Out-File $LogFile -Append -Force
	Write-Host "* secure1.key NON GENERATA" -ForegroundColor "red"
	Sleep 5
	Exit
}
[array]$key2 = (1..24 | % {(Get-Random -Minimum 1 -Maximum 200)})
$key2 | Out-File $clonedir\secure2.key
if(Test-Path $clonedir\secure2.key){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure2.key generata" | Out-File $LogFile -Append -Force
}
elseif(!(Test-Path $clonedir\secure2.key)){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure2.key NON GENERATA" | Out-File $LogFile -Append -Force
	Write-Host "* secure2.key NON GENERATA" -ForegroundColor "red"
	Sleep 5
	Exit
}
#genero i files criptati
((ConvertTo-SecureString $psw_joiner -AsPlainText -Force) | ConvertFrom-SecureString -Key $key1) | Out-File $clonedir\secure1
((ConvertTo-SecureString $psw_installer -AsPlainText -Force) | ConvertFrom-SecureString -Key $key2) | Out-File $clonedir\secure2
if(Test-Path $clonedir\secure1){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure1 generata" | Out-File $LogFile -Append -Force
}
elseif(!(Test-Path $clonedir\secure1)){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure1 NON GENERATA" | Out-File $LogFile -Append -Force
	Write-Host "* secure1 NON GENERATA" -ForegroundColor "red"
	Sleep 5
	Exit
}
if(Test-Path $clonedir\secure2){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure2 generata" | Out-File $LogFile -Append -Force
}
elseif(!(Test-Path $clonedir\secure2)){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure2 NON GENERATA" | Out-File $LogFile -Append -Force
	Write-Host "* secure2 NON GENERATA" -ForegroundColor "red"
	Sleep 5
	Exit
}

################################################
#----------------ABILITAZIONE AUTOLOGON DI Script1.ps1 & SPEGNIMENTO
Write-Host "`n* INSERISCO IN AUTOLOGON AUTOLOGON LE IMPOSTAZIONI NECESSARIE AL PRIMO PASSAGGIO DI POST-CLONAZIONE..." 
Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1"
Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value "Administrator"
Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value "$psw_admin"
if(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon")).AutoAdminLogon -EQ 1){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] AutoAdminLogon impostato su 1: ok" | Out-File $LogFile -Append -Force
}
elseif(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon")).AutoAdminLogon -NE 1){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] AutoAdminLogon NON IMPOSTATO su 1" | Out-File $LogFile -Append -Force
	Write-Host "* AutoAdminLogon NON IMPOSTATO su 1" -ForegroundColor red
	Sleep 5
	Exit
}
if(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName")).DefaultUserName -EQ 'Administrator'){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] AutoAdminLogon impostato con Administrator: ok" | Out-File $LogFile -Append -Force
}
elseif(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName")).DefaultUserName -NE 'Administrator'){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] AutoAdminLogon NON IMPOSTATO con Administrator" | Out-File $LogFile -Append -Force
	Write-Host "* AutoAdminLogon NON IMPOSTATO con Administrator" -ForegroundColor red
	Sleep 5
	Exit
}
if(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword")).DefaultPassword -EQ $psw_admin){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DefaultPassword ok" | Out-File $LogFile -Append -Force
}
elseif(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword")).DefaultPassword -NE $psw_admin){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DefaultPassword NON ok" | Out-File $LogFile -Append -Force
	Write-Host "* DefaultPassword NON ok" -ForegroundColor red
	Sleep 5
	Exit
}
if(New-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name Script1_Start -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File $clonedir\Script1.ps1"){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Script1 inserito in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File $LogFile -Append -Force
}
Write-Host -NoNewLine "`n* QUANDO VUOI PREMI UN TASTO QUALSIASI, DOPODICHE' SPEGNERO' IL PC" 
$x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Stop-Computer