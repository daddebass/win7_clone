#imposto il colore per Script2.ps1, Giallo
[console]::ForegroundColor = "DarkYellow"
$Host.UI.RawUI.WindowTitle = "Script2.ps1"

################################################
#----------------DICHIARAZIONE CARTELLE DI LAVORO, LOG, DIM. FINESTRA
[string]$data = Get-Date -UFormat "%d-%m-%y"
[string]$systemdrive = $env:SystemDrive
[string]$clonedir = "$PSScriptRoot\"
[string]$Logfile = "$clonedir\Script2_$data.log"
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Script2 Log---------------" | Out-File $LogFile -Append -Force
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
#----------------PULIZIA SCHERMO, STOP AL SERVIZIO FIREWALL E DISABILITA AUTOLOGON Script2
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
Write-Host "`n* DISABILITO L'AUTOLOGON DI Script2.ps1" 
Remove-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Script2_Start
if((Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Script2_Start -ErrorAction SilentlyContinue) -EQ $null){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Script2 rimosso da HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File $LogFile -Append -Force
}
Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "0"
Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value ""
Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value ""
if(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon")).AutoAdminLogon -EQ 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] AutoAdminLogon impostato su 0: ok" | Out-File $LogFile -Append -Force
}
elseif(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon")).AutoAdminLogon -NE 0){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] AutoAdminLogon NON IMPOSTATO su 0" | Out-File $LogFile -Append -Force
	Write-Host "* AutoAdminLogon NON IMPOSTATO su 0" -ForegroundColor red
	Sleep 5
	Exit
}
if(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName")).DefaultUserName -EQ ''){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] AutoAdminLogon re-impostato: ok" | Out-File $LogFile -Append -Force
}
elseif(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName")).DefaultUserName -NE ''){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] AutoAdminLogon NON RE-IMPOSTATO" | Out-File $LogFile -Append -Force
	Write-Host "* AutoAdminLogon NON RE-IMPOSTATO" -ForegroundColor red
	Sleep 5
	Exit
}
if(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword")).DefaultPassword -EQ ''){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DefaultPassword re-impostata: ok" | Out-File $LogFile -Append -Force
}
elseif(((Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword")).DefaultPassword -NE ''){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DefaultPassword NON RE-IMPOSTATA" | Out-File $LogFile -Append -Force
	Write-Host "* DefaultPassword NON RE-IMPOSTATA" -ForegroundColor red
	Sleep 5
	Exit
}

################################################
#----------------JOIN, COPIA IN SHARE DATI POSTAZIONE & schtasks PER E-MAIL
[array]$key1 = Get-Content $clonedir\secure1.key
Write-Host "`n* JOIN AL DOMINIO..."
if($key1){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure1.key presente" | Out-File $LogFile -Append -Force
	[string]$psw_joiner = (New-Object system.Management.Automation.PSCredential("SQLPSX", (ConvertTo-SecureString (Get-content $clonedir\secure1) -Key $key1))).GetNetworkCredential().Password
	$credential_joiner = New-Object System.Management.Automation.PSCredential("lib.unimib.it\joiner",($psw_joiner | ConvertTo-SecureString -AsPlainText -Force))
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] credenziali di lib\joiner de-criptate e ok" | Out-File $LogFile -Append -Force
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] avvio il join su $($env:ComputerName)" | Out-File $LogFile -Append -Force
	$Join_Result = (Add-Computer -DomainName "lib.unimib.it" -Credential $credential_joiner -Force -Verbose -PassThru).HasSucceeded
	if($Join_Result -EQ "True"){
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] $($env:ComputerName) aggiunta dal dominio" | Out-File $LogFile -Append -Force
	}
	elseif($Join_Result -NE "True"){
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] $($env:ComputerName) NON aggiunta dal dominio" | Out-File $LogFile -Append -Force
		Write-Host "* $($env:ComputerName) NON aggiunta dal dominio" -ForegroundColor red
		Sleep 5
		Exit
	}
}
elseif(!($key1)){
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure1.key NON presente" | Out-File $LogFile -Append -Force
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] $($env:ComputerName) NON aggiunta dal dominio" | Out-File $LogFile -Append -Force
	Write-Host "* $($env:ComputerName): secure1.key NON presente, NON aggiunta dal dominio" -ForegroundColor red
	Sleep 5
	Exit
}
if(Test-Path $clonedir\recovery*.inf){
	#copia del file di recovery
	Write-Host "* COPIO IN \\lib\shareddata I DATI DI QUESTA MACCHINA`n"
	Start-Sleep 5
	[array]$key2 = Get-Content $clonedir\secure2.key
	if($key2){
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure2.key presente" | Out-File $LogFile -Append -Force
		[string]$psw_installer = (New-Object system.Management.Automation.PSCredential("SQLPSX", (ConvertTo-SecureString (Get-content $clonedir\secure2) -key $key2))).GetNetworkCredential().Password
		$credential_installer = New-Object System.Management.Automation.PSCredential("lib.unimib.it\installer",($psw_installer | ConvertTo-SecureString -AsPlainText -Force))
		New-PSDrive -Name S -Root \\10.109.8.21\shareddata\client\recovery_mac_ip_nome_inf -PSProvider FileSystem -Credential $credential_installer | Out-Null
		Copy-Item $clonedir\recovery*.inf S:
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] LA MACCHINA NON ERA PRESENTE IN MAC_IP_NOME.INF. I DATI DEL PC SONO STATI COPIATI IN shareddata\client\recovery_mac_ip_nome_inf" | Out-File $LogFile -Append -Force
		Remove-PSDrive S
		#inizializzo l'oggetto $mail che sarà lo script incaricato di inviare la mail e che verrà copiato in $clonedir
		$mail =
@'
Sleep 15
#attendo che il servizio WinRM sia acceso per proseguire con lo script
while((Get-Wmiobject -Class "Win32_Service" -filter "Name='WinRM'").State -NE "Running"){Start-Sleep -m 500}
[string]$clonedir = "$PSScriptRoot\"
[string]$hn = $env:ComputerName
$smtpFrom = "$hn@lib.unimib.it"
$smtpTo = "lib@didattica.unimib.it"
$message = New-Object System.Net.Mail.MailMessage $smtpfrom, $smtpto
$message.Subject = "$hn NON trovata in mac_ip_nome.inf"
$message.IsBodyHTML = $true
$message.Body = "La postazione in oggetto non era in mac_ip_nome.inf al momento della clonazione. <b><font color=red></b></font> <br>"
$message.Body += "Copia e incolla (o sostituisci) la seguente stringa nel file \\lib\Shareddata\lib\client\mac_ip_nome.inf: <b></b> <br>"
$message.Body += "<br>"
$message.Body += Get-Content $clonedir\recovery*.inf
#spedisco, impostando la porta 25 e l'smtp di S.I.
$smtp = New-Object Net.Mail.SmtpClient("smtp.unimib.it", 25)
$smtp.Send($message)
#rimuovi il file di recovery e la scheduled task che ha inviato la mail, creata in Script2.ps1
Remove-Item $clonedir\recovery*.inf
schtasks /delete /tn "SendMailRecovery_MacIpNomeInf" /f
#rimuovo tramite cmd (non posso eliminarlo tramite PS essendo lo script attivo) lo script $clonedir\SendRecoveryEmail.ps1
cmd.exe /c del $clonedir\SendRecoveryEmail.ps1
'@
		#creo lo script SendRecoveryEmail.ps1
		$mail | Out-File $clonedir\SendRecoveryEmail.ps1
		if(Test-Path $clonedir\SendRecoveryEmail.ps1){
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] creato lo script $clonedir\SendRecoveryEmail.ps1" | Out-File $LogFile -Append -Force
			#pianifico, tramite lo scheduler di sistema (Utility schtasks), una sola volta al prossimo boot (quello dopo la post-clonazione), l'invio della mail.
			schtasks /create /tn SendMailRecovery_MacIpNomeInf /tr "powershell.exe -file $clonedir\SendRecoveryEmail.ps1" /sc ONSTART /ru lib\installer /rp $psw_installer
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] mail tramite lo scheduler di sistema (Utility schtasks) programmata " | Out-File $LogFile -Append -Force
		}
	}
	if(!($key2)){
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] secure2.key NON presente" | Out-File $LogFile -Append -Force
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] LA MACCHINA NON ERA PRESENTE IN MAC_IP_NOME.INF. I DATI DEL PC NON SONO STATI COPIATI IN shareddata\client\recovery_mac_ip_nome_inf" | Out-File $LogFile -Append -Force
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] non creato lo script $clonedir\SendRecoveryEmail.ps1" | Out-File $LogFile -Append -Force
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] mail tramite lo scheduler di sistema (Utility schtasks) NON programmata " | Out-File $LogFile -Append -Force
		Write-Host "* Molti errori! Vedi log!" -ForegroundColor red
		Sleep 5
		Exit
	}
}

################################################
#----------------RICAVO $id_lab (per il manage gruppi, %desktoplib% e crea WOL), SET DELLA VARIABILE %desktoplib%, SET PROXY E RI-AVVIO INTERFACCE VIRTUALI DI VMWARE
[string]$hn = $env:ComputerName
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] HostName: $hn" | Out-File $LogFile -Append -Force
if($hn -NotMatch "MASTER"){
	switch($hn){
		#solo per le macchine tutor come LAB8T1TUTOR, che contengono 3 "T" e non la "P"
		{$hn -Match "T" -And $hn -NotMatch "P" -And ([regex]::Matches($hn,"T").Count) -EQ 3} {[string]$id_lab = ([regex]::Split($hn,"TU")[0]).ToLower()}
		#solo per le macchine tutor come LAB711TUTOR, con due "T" e non hanno la "P"
		{$hn -Match "T" -And $hn -NotMatch "P" -And ([regex]::Matches($hn,"T").Count) -EQ 2} {[string]$id_lab = ($hn.split('T')[0]).ToLower()}
		#per host come LAB8T1P1, che contengono sia "P" che "T"
		{$hn -Match "P" -And $hn -Match "T"} {[string]$id_lab = ($hn.split('P')[0]).ToLower()}
		#solo per macchine con nome come LAB712P4 che contiene solo "P"
		{$hn -Match "P" -And $hn -NotMatch "T"} {[string]$id_lab = ($hn.split('P')[0]).ToLower()}
		#per macchine DOCENTE &/O SCANNER
		{$hn -Match "SCANNER"} {[string]$id_lab = ($hn.split('S')[0]).ToLower()}
		{$hn -Match "DOCENTE"} {[string]$id_lab = ($hn.split('D')[0]).ToLower()}
	}
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] id_lab: $id_lab" | Out-File $LogFile -Append -Force
	[string]$mac = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE AND NOT Description LIKE 'VMWare%'").MACAddress
	[string]$Ip = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.InterfaceIndex -EQ ((Get-WmiObject Win32_NetworkAdapter | Where {$_.MACAddress -EQ $mac}).InterfaceIndex)}).IPAddress
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Mac Address: $mac" | Out-File $LogFile -Append -Force
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] IP: $Ip" | Out-File $LogFile -Append -Force
	switch($Ip.remove(6)){
		#per la var. $proxy mi baso sulla subnet del laboratorio
		{($_ -EQ "10.101") -OR ($_ -EQ "10.103") -OR ($_ -EQ "10.105") -OR $_ -EQ ("10.109")}{
			[string]$desktoplib = "\\green08\DfsRootDesktop\$id_lab"
			[string]$proxy = "proxyu9"
		}
		{($_ -EQ "10.107") -OR ($_ -EQ "10.114")}{
			[string]$desktoplib = "\\blue03\DfsRootDesktop\$id_lab"
			[string]$proxy = "proxyu7"
		}
		{($_ -EQ "10.108")}{
			[string]$desktoplib = "\\blue-v20\med\desktop\$id_lab"
			[string]$proxy = "proxyu8"
		}
		{($_ -EQ "10.116")}{
			[string]$desktoplib = "\\blue14\DfsRootScifor$\desktop\$id_lab"
			[string]$proxy = "proxyu16"
		}
		{($_ -EQ "10.146")}{
			[string]$desktoplib = "\\blue03\DfsRootDesktop\$id_lab"
			[string]$proxy = "proxyu7"
		}
		{($_ -EQ "10.188")}{
			#in multimedica niente desktop
			[string]$proxy = "proxyu7"
		}
	}
	if($desktoplib){
		Write-Host "* Desktoplib: $desktoplib"
		[Environment]::SetEnvironmentVariable("desktoplib", "$desktoplib", "Machine")
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] DesktopLib: $desktoplib" | Out-File $LogFile -Append -Force
	}
	if($proxy){
		& "$systemdrive\Program Files (x86)\Forefront TMG Client\FwcTool.exe" SetManualServer /g /server:$proxy
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Proxy: $proxy" | Out-File $LogFile -Append -Force
	}
	elseif((!($desktoplib)) -AND (!($proxy))){
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] NON son riuscito a ricavare desktoplib e proxy!" | Out-File $LogFile -Append -Force
		Write-Host "* NON son riuscito a ricavare desktoplib e proxy!" -ForegroundColor red
		Sleep 5
		Exit
	}
}
#interfacce virtuali di vmware ri-avviate se presenti
Write-Host "`n* ABILITO LE INTERFACCE VIRTUALI DI VMWARE PLAYER - se presenti..." 
if((Get-WmiObject Win32_NetworkAdapter | where {$_.ServiceName -EQ "VMnetAdapter"}).InterfaceIndex){
	devcon.exe enable *VMnetAdapter* | Out-Null
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Interfacce VMWARE abilitate" | Out-File $LogFile -Append -Force
}

################################################
#----------------MANIPOLAZIONE GRUPPI LOCALI
if($hn -NotMatch "MASTER"){
	Write-Host "`n* MANIPOLAZIONE DEI GRUPPI"
	Start-Sleep 2
	#devono rimanere soltanto i labxxxlocalpowerusers, labxxxlocalusers, labxxxlocaladmins dei lab che NON mi interessano
	[array]$Members_LocalUsers_ToRemove = @(([ADSI]"WinNT://localhost/Users,group").psbase.Invoke("Members")) | % {([ADSI]$_).InvokeGet("Name")} |? {$_ -NotMatch $id_lab} |? {$_ -Match "lab"}
	[array]$Members_LocalPowerusers_ToRemove = @(([ADSI]"WinNT://localhost/Power Users,group").psbase.Invoke("Members")) | % {([ADSI]$_).InvokeGet("Name")} |? {$_ -NotMatch $id_lab} |? {$_ -Match "lab"}
	[array]$Members_LocalAdministrators_ToRemove = @(([ADSI]"WinNT://localhost/Administrators,group").psbase.Invoke("Members")) | % {([ADSI]$_).InvokeGet("Name")} |? {$_ -NotMatch $id_lab} |? {$_ -Match "lab"}
	#nel caso in cui la macchina sia destinata a + di un lab
    if(($Members_LocalUsers_ToRemove -NE $null) -AND ($Members_LocalPowerusers_ToRemove -NE $null) -AND ($Members_LocalAdministrators_ToRemove -NE $null)){
		Write-Host "* SET DEI GRUPPI IN LOCALUSERS"
		foreach($Member in $Members_LocalUsers_ToRemove){
			Write-Host "Rimozione del sotto-gruppo -->" $Member
			($Computer.psbase.children.find("Users")).Remove("WinNT://" + $Domain + "/" + $Member)
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] eliminato il sotto-gruppo: $Member" | Out-File $LogFile -Append -Force
		}
	   Write-Host "* SET DEI GRUPPI IN LOCALPOWERUSERS" 
	   foreach($Member in $Members_LocalPowerusers_ToRemove){
			Write-Host "Rimozione del sotto-gruppo -->" $Member
			($Computer.psbase.children.find("Power Users")).Remove("WinNT://" + $Domain + "/" + $Member)
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] eliminato il sotto-gruppo: $Member" | Out-File $LogFile -Append -Force
		}
	   Write-Host "* SET DEI GRUPPI IN LOCALADMINISTRATORS" 
	   foreach($Member in $Members_LocalAdministrators_ToRemove){
			Write-Host "Rimozione del sotto-gruppo -->" $Member
			($Computer.psbase.children.find("Administrators")).Remove("WinNT://" + $Domain + "/" + $Member)
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] eliminato il sotto-gruppo: $Member" | Out-File $LogFile -Append -Force
		}
	}
	else{
		#non ci sono gruppi da rimuovere
		Write-Host "* IN QUESTA MACCHINA NON DEVO MANIPOLARE I GRUPPI"
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] in questa macchina non si rimuovono i sotto-gruppi" | Out-File $LogFile -Append -Force
	}
}

################################################
#----------------CREAZIONE DEL FILE C:\ACCENDI_LABXXX.CMD IN C:\ & link su desktop
if($hn -NotMatch "MASTER"){
	#se laboratorio nuovo target_lab è $null
	[array]$target_lab = ((Get-Content $clonedir\mac_ip_nome.inf) | Select-String -Pattern $id_lab) |? {$_ -NotMatch "<<<" + $id_lab + ">>>" -AND $_ -NotMatch "TUTOR" -AND $_ -NotMatch "MASTER"}
	if($target_lab){
		Write-Host "`n* IMPOSTO IL FILE .cmd WOL_LAB IN C:\"
		foreach ($client in $target_lab){
			[string]$ip = ([string]$client).Split("=")[1]
			#a wolcmd non piacciono i ":" nel mac address...
			[string]$mac = (([string]$client).Split("=")[0]) -Replace ':',''
			"start wolcmd.exe $mac $ip 255.255.248.0 8900" | Out-File "C:\ACCENDI_$id_lab.cmd" -Append -Force -Encoding UTF8
		}
		#imposta i permessi di lettura e esecuzione ad everyone
		$permessi_WOL = Get-Acl "C:\ACCENDI_$id_lab.cmd"
		$SET = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","ReadAndExecute","Allow")
		$permessi_WOL.SetAccessRule($SET)
		Set-Acl "C:\ACCENDI_$id_lab.cmd" $permessi_WOL
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] creato, in c:\, il file ACCENDI_$id_lab.cmd" | Out-File $LogFile -Append -Force
		if($hn -Match "TUTOR"){
			#se è tutor imposto il link al WOL sul desktop
			Write-Host "* SETTO IL LINK ALLO SVEGLIA LAB SUL DESKTOP---"	
			$WshShell_wol = New-Object -ComObject WScript.Shell
			$Shortcut_wol = $WshShell_wol.CreateShortcut("C:\Users\Public\Desktop\ACCENDI_$id_lab.lnk")
			$Shortcut_wol.TargetPath = "C:\ACCENDI_$id_lab.cmd"
			$Shortcut_wol.Save()
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] impostato link su desktop al file C:\ACCENDI_LABXXX.CMD" | Out-File $LogFile -Append -Force
		}
	}
	elseif(!($target_lab)){
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] NON creato, in c:\, il file ACCENDI_$id_lab.cmd" | Out-File $LogFile -Append -Force
	}
}

################################################
#----------------RESET SUS CLIENTID
if($hn -NotMatch "MASTER"){
	Write-Host "`n* STO RE-INIZIALIZZANDO Windows Update service`n" 
	$WUpdtService = Get-Wmiobject -Class "Win32_Service" -Filter "Name='wuauserv'"
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] FwcAgent: $((Stop-Service wuauserv -WarningAction SilentlyContinue -PassThru).Status)" | Out-File $LogFile -Append -Force
	do{
		Start-Sleep -m 250
	}while((Get-Wmiobject -Class "Win32_Service" -filter "Name='wuauserv'").State -EQ "Running")
	$WUpdtregkey = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
	if($WUpdtregkey.SUSclientid){
		(Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientId" -Value "")
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] SUSclientId re-impostato" | Out-File $LogFile -Append -Force
	}
	if($WUpdtregkey.SusClientIdValidation){
		(Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "SusClientIdValidation" -Value "")
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] SusClientIdValidation re-impostato" | Out-File $LogFile -Append -Force
	}
	if($WUpdtregkey.PingID){
		(Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "PingID" -Value "")
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] PingID re-impostato" | Out-File $LogFile -Append -Force
	}
	if($WUpdtregkey.AccountDomainSid){
		(Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Name "AccountDomainSid" -Value "")
		"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] AccountDomainSid re-impostato" | Out-File $LogFile -Append -Force
	}
}

################################################
#----------------ELIMINAZIONE FILES DI LAVORAZIONE, PROFILI INUTILI, IMPOSTA DATA CLONAZIONE, LINK A LOGON_SCRIPT (rimosso in _PreClone.ps1)
Write-Host "`n* STO ELIMINANDO I FILES DI LAVORAZIONE`n" 
if(Test-Path $clonedir\SendRecoveryEmail.ps1){
	Remove-Item $clonedir\mac_ip_nome.inf
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] eliminato solo mac_ip_nome.inf, il file di recovery mi serve poi per l'invio della mail" | Out-File $LogFile -Append -Force
}
elseif(!(Test-Path $clonedir\SendRecoveryEmail.ps1)){
	Remove-Item $clonedir\*.inf
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] eliminati i files di lavorazione *.inf" | Out-File $LogFile -Append -Force
}
if(Test-Path $clonedir\secure*){
	Remove-Item $clonedir\secure*
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] eliminati i files secure*" | Out-File $LogFile -Append -Force
}
if($hn -NotMatch "MASTER"){
	#se c'è almeno un utente che NON sia Administrator o Public avvio delprof2
	if(Get-ChildItem C:\Users\ -Exclude Administrator,Public){
		Write-Host "* ELIMINO I PROFILI INUTILI"
		[string]$Delprof2Args = '/u /ed:admin* /i'
		[array]$ProfilesToDelete = (Get-ChildItem C:\Users\ -Exclude Administrator,Public)
		if(Start-Process delprof2 -ArgumentList $Delprof2Args -PassThru){
			#ne attendo la conclusione
			Wait-Process -Id (Get-Process delprof2).Id
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] delprof2 avviato" | Out-File $LogFile -Append -Force
		}
		foreach($Profile in $ProfilesToDelete){
			"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] eliminato: $Profile" | Out-File $LogFile -Append -Force
		}
	}
}
#re-imposto il link a logon_script...
[string]$data_ora_clonazione = Get-Date -format d/M/yyyy" "-" "%H:mm
Set-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM" -Name "DATA_CLONAZIONE" -Value $data_ora_clonazione
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] data & ora clonazione: $data_ora_clonazione" | Out-File $LogFile -Append -Force
$WshShell_logonscript = New-Object -ComObject WScript.Shell
$Shortcut_logonscript = $WshShell_logonscript.CreateShortcut("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\LOGON_SCRIPT.lnk")
$Shortcut_logonscript.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$Shortcut_logonscript.Arguments = "C:\LOGON_SCRIPT.ps1"
$Shortcut_logonscript.IconLocation = "powershell.exe,0"
$Shortcut_logonscript.Description ="LOGON SCRIPT: BGINFO E PRINTERSET"
#...ne imposto l'esecuzione ridotto a icona
$Shortcut_logonscript.WindowStyle = 7
$Shortcut_logonscript.Save()
if(Test-Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\LOGON_SCRIPT.lnk'){	
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] LINK A C:\LOGON_SCRIPT.ps1 CREATO IN C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" | Out-File $LogFile -Append -Force
}
Write-Host "`n* FACCIO GIRARE BGINFO E RIAVVIO`n"
if(Start-Process C:\Windows\System32\Bginfo.exe -ArgumentList 'C:\bginfo.bgi /timer:0 /NOLICPROMPT /silent' -PassThru){
	Wait-Process -Id (Get-Process Bginfo).Id
	Copy-Item C:\temp\backgroundDefault.jpg C:\Windows\System32\oobe\info\backgrounds
	"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')] Bginfo aggiornato" | Out-File $LogFile -Append -Force
}
Start-Sleep 3
"[$(Get-Date -UFormat '%d-%m-%y-%H:%M:%S')]--PROCEDURA DI POST-CLONAZIONE TERMINATA--" | Out-File $LogFile -Append -Force
Restart-Computer