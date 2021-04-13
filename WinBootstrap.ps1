#Requires -Version 3.0
# Compile https://gallery.technet.microsoft.com/PS2EXE-GUI-Convert-e7cb69d5/file/172772/21/PS2EXE-GUI.zip




#---------------------------------------------------------[Script Parameters]------------------------------------------------------
[CmdletBinding()]

Param (
  ### Custom block start
  [string]$UserName = "",
  [string]$Password = "",
  [string]$SNMPManager = "*",
  [string]$ROCommuniti = "public",

  ### Custom block end
  [string]$SubjectName = $env:COMPUTERNAME,
  [int]$CertValidityDays = 1095,
  [switch]$SkipNetworkProfileCheck,
  $CreateSelfSignedCert = $true,
  [switch]$ForceNewSSLCert,
  [switch]$GlobalHttpFirewallAccess,
  [switch]$DisableBasicAuth = $false,
  [switch]$EnableCredSSP
)

if (!$username) { Write-Error "parameter -username is undefined"; exit 1 }
if (!$password) { $password = ""; }

#----------------------------------------------------------[Declarations]----------------------------------------------------------

$VerbosePreference = "Continue"
$logFile = "C:\WinBootstrap.log"

#-----------------------------------------------------------[Functions]------------------------------------------------------------

### Custom block start

<# function Template {
  Param ()
  Begin {
    $Message = "`n" + "[Start " + $MyInvocation.MyCommand.Name + "]"
    Write-Host $Message
  }
  Process {
    Try {

      Write-Verbose ("Adding this verbose")

    }
    Catch {
      Write-Error ($_.Exception) + "`n"
      Break
    }
  }
  End {
    If ($?) {
      $Message = "[End " + $MyInvocation.MyCommand.Name + "]" + "`n"
      Write-Host -ForegroundColor "Green" $Message
    }
  }
} #>

function Disable-ComplexPassword {
  Param ()
  Begin {
    $Message = "`n" + "[--- Start " + $MyInvocation.MyCommand.Name + " ----]"
    Write-Host $Message
  }
  Process {
    Try {

      $seccfg = [IO.Path]::GetTempFileName()
      secedit /export /cfg $seccfg
      (Get-Content $seccfg) | Foreach-Object { $_ -replace "PasswordComplexity\s*=\s*1", "PasswordComplexity=0" } | Set-Content $seccfg
      secedit /configure /db $env:windir\security\new.sdb /cfg $seccfg /areas SECURITYPOLICY
      del $seccfg

    }
    Catch {
      Write-Error ($_.Exception)
      Break
    }
  }
  End {
    If ($?) {
      $Message = "[---- End " + $MyInvocation.MyCommand.Name + " ----]" + "`n"
      Write-Host -ForegroundColor "Green" $Message
    }
  }
}

function New-LocalAdmin {
  Param([string]$username, [string]$password)
  Begin {
    $Message = "`n" + "[--- Start " + $MyInvocation.MyCommand.Name + " ----]"
    Write-Host $Message
  }
  Process {
    Try {

      $user = Get-LocalUser | Where-Object { $_.Name -eq $username }
      $admGroup = (get-wmiobject win32_group -Filter "SID='S-1-5-32-544'").Name

      if (-not $user) {
        Write-Host "Creating user $username ..."
        $Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer"
        $LocalAdmin = $Computer.Create("User", $username)
        $LocalAdmin.setPassword($password)
        $LocalAdmin.UserFlags = 64 + 65536
        $LocalAdmin.setInfo()


        Write-Host "Adding $username  to group $admGroup ..."
        $groupExpression = "WinNT://$Env:COMPUTERNAME/$admGroup,Group"
        $AdminGroup = [ADSI]$groupExpression
        $AdminGroup.Add("WinNT://$username,User")
        $AdminGroup.SetInfo()
      }
      Else {
        Write-Host -Foreground Yellow "User $username already exist"

        if (-not (Get-LocalGroupMember -Group $admGroup -Member $user)) {
          Write-Host "Adding $username  to group $admGroup"
          $groupExpression = "WinNT://$Env:COMPUTERNAME/$admGroup,Group"
          $AdminGroup = [ADSI]$groupExpression
          $AdminGroup.Add("WinNT://$username,User")
          $AdminGroup.SetInfo()
        }
        Else {
          Write-Host -Foreground Yellow "User $username already member $admGroup"
        }
      }

      Write-Host -Foreground Yellow "Change password for user $username "
      $objUser = [ADSI]"WinNT://$Env:COMPUTERNAME/$username,user"
      $objUser.setPassword($password)
      $objUser.UserFlags = 64 + 65536
      $objUser.setInfo()

    }
    Catch {
      Write-Error ($_.Exception)
      Break
    }
  }
  End {
    If ($?) {
      $Message = "[---- End " + $MyInvocation.MyCommand.Name + " ----]" + "`n"
      Write-Host -ForegroundColor "Green" $Message
    }
  }
}

function Hide-User {
  Param([string]$username)
  Begin {
    $Message = "`n" + "[--- Start " + $MyInvocation.MyCommand.Name + " ----]"
    Write-Host $Message
  }
  Process {
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -Name $username -PropertyType DWORD -Value 0
  }
  End {
    If ($?) {
      $Message = "[---- End " + $MyInvocation.MyCommand.Name + " ----]" + "`n"
      Write-Host -ForegroundColor "Green" $Message
    }
  }
}

function Enable-RDP {
  Param()
  Begin {
    $Message = "`n" + "[--- Start " + $MyInvocation.MyCommand.Name + " ----]"
    Write-Host $Message
  }
  Process {
    Try {


      $OSCaption = $(wmic os get Caption)[2].ToUpper()
      if ( $OSCaption.Contains("HOME") ) {
        Write-Host "Not working on Windows Home Edition"
        return
      }

      Set-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server" -name "fDenyTSConnections" -Value 0
      Set-ItemProperty -Path  "HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" -name "UserAuthentication" -Value 1
      $RDP = Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\CIMV2\TerminalServices -ErrorAction Stop
      $result = $RDP.SetAllowTsConnections(1, 1)
      if ($result.ReturnValue -eq 0) {
        Write-Host "Enabled RDP Successfully"
      }
      else {
        Write-Host "Failed to enabled RDP"
      }
      try {
        #Enable-NetFirewallRule -DisplayGroup "Remote Desktop*"
        Get-NetFirewallRule -DisplayName "Remote Desktop*" | Set-NetFirewallRule -enabled true
      }
      catch {
        #Win7 #netsh advfirewall firewall set service type=remotedesktop mode=enable
        netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
      }

    }
    Catch {
      Write-Error ($_.Exception)
      Break
    }
  }
  End {
    If ($?) {
      $Message = "[---- End " + $MyInvocation.MyCommand.Name + " ----]" + "`n"
      Write-Host -ForegroundColor "Green" $Message
    }
  }
}

function Set-NetworksAsPrivate {
  Param()
  Begin {
    $Message = "`n" + "[--- Start " + $MyInvocation.MyCommand.Name + " ----]"
    Write-Host $Message
  }
  Process {
    Try {

      Set-NetConnectionProfile -NetworkCategory Private

    }
    Catch {
      Write-Error ($_.Exception)
      # Get network connections for Windows 7
      $networkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]"{DCB00C01-570F-4A9B-8D69-199FDBA5723B}"))
      $connections = $networkListManager.GetNetworkConnections()
      $connections | % { $_.GetNetwork().SetCategory(1) }
    }
  }
  End {
    If ($?) {
      $Message = "[---- End " + $MyInvocation.MyCommand.Name + " ----]" + "`n"
      Write-Host -ForegroundColor "Green" $Message
    }
  }
}

function Set-HostnameByMAC {
  Param ([string] $mac)
  Begin {
    $Message = "`n" + "[Start " + $MyInvocation.MyCommand.Name + "]"
    Write-Host $Message
  }
  Process {
    Try {

      $mac = $mac -replace '[-]', ''
      $ComputerName = "pc-$mac"
      Rename-Computer -NewName $ComputerName
      $oldHostname = "$env:COMPUTERNAME"
      $newHostname = "$ComputerName"

      <#
      # Change hostname without reboot
      Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname"
      Remove-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname"

      New-PSDrive -name HKU -PSProvider "Registry" -Root "HKEY_USERS"

      Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\Computername" -name "Computername" -value $ComputerName
      Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Computername\ActiveComputername" -name "Computername" -value $ComputerName
      Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "Hostname" -value $ComputerName
      Set-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -name "NV Hostname" -value  $ComputerName
      Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "AltDefaultDomainName" -value $ComputerName
      Set-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -name "DefaultDomainName" -value $ComputerName
      #Set-ItemProperty -path "HKU:\.Default\Software\Microsoft\Windows Media\WMSDK\General" -name "Computername" -value $ComputerName
      #>



      Write-Host "Changed $oldHostname -> $newHostname"
      $result = $ComputerName

    }
    Catch {
      Write-Error ($_.Exception)
      Break
    }
  }
  End {
    If ($?) {
      $Message = "[End " + $MyInvocation.MyCommand.Name + "]" + "`n"
      Write-Host -ForegroundColor "Green" $Message
    }
  }
}

function Enable-SNMP {
  Param ( [string]$Manager, [string]$Communiti )
  Begin {
    $Message = "`n" + "[Start " + $MyInvocation.MyCommand.Name + "]"
    Write-Host $Message
  }
  Process {
    Try {

      #Gather list of currently enabled Windows features and check for SNMP
      $TempFile = "$env:temp\TempFile.log"
      & dism.exe /Online /Get-Features /Format:Table | Out-File $TempFile -Force

      $WinFeatures = (Import-Csv -Delimiter '|' -Path $TempFile -Header Name, state | Where-Object { $_.State -eq "Enabled " }) | Select-Object Name

      Remove-Item -Path $TempFile

      #If SNMP service not installed, run the installer
      if ($WinFeatures | Where-Object { $_.Name.Trim() -like "SNMP*" }) {
        Write-Host "SNMP service already installed."
      }
      else {
        Write-Host "Enabling the SNMP service."
        & dism.exe /Online /Enable-Feature /FeatureName:SNMP
      }

      Write-Host "Configuring SNMP Services..."

      #Set SNMP Permitted Manager(s) ** WARNING : This will over write current settings **
      reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SNMP\Parameters\PermittedManagers" /v 1 /t REG_SZ /d $Manager /f | Out-Null
      reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" /v $Communiti /t REG_DWORD /d 4 /f | Out-Null
    }
    Catch {
      Write-Error ($_.Exception) + "`n"
      Break
    }
  }
  End {
    If ($?) {
      $Message = "[End " + $MyInvocation.MyCommand.Name + "]" + "`n"
      Write-Host -ForegroundColor "Green" $Message
    }
  }
}

function Disable-Defender {
  Param ()
  Begin {
    $Message = "`n" + "[Start " + $MyInvocation.MyCommand.Name + "]"
    Write-Host $Message
  }
  Process {
    Try {

      Set-MpPreference -DisableRealtimeMonitoring $true >nul 2>&1

    }
    Catch {
      Write-Error ($_.Exception) + "`n"
      Break
    }
  }
  End {
    If ($?) {
      $Message = "[End " + $MyInvocation.MyCommand.Name + "]" + "`n"
      Write-Host -ForegroundColor "Green" $Message
    }
  }
}

function Disable-Firewall {
  Param ()
  Begin {
    $Message = "`n" + "[Start " + $MyInvocation.MyCommand.Name + "]"
    Write-Host $Message
  }
  Process {
    Try {

      netsh advfirewall set privateprofile state off >nul 2>&1
      netsh advfirewall set domainprofile state off >nul 2>&1
      netsh advfirewall set publicprofile state off >nul 2>&1

    }
    Catch {
      Write-Error ($_.Exception) + "`n"
      Break
    }
  }
  End {
    If ($?) {
      $Message = "[End " + $MyInvocation.MyCommand.Name + "]" + "`n"
      Write-Host -ForegroundColor "Green" $Message
    }
  }
}
### Custom block end


Function Write-Log {
  $Message = $args[0]
  Write-EventLog -LogName Application -Source $EventSource -EntryType Information -EventId 1 -Message $Message
}

Function Write-VerboseLog {
  $Message = $args[0]
  Write-Verbose $Message
  Write-Log $Message
}

Function Write-HostLog {
  $Message = $args[0]
  Write-Output $Message
  Write-Log $Message
}

Function New-LegacySelfSignedCert {
  Param (
    [string]$SubjectName,
    [int]$ValidDays = 1095
  )

  $hostnonFQDN = $env:computerName
  $hostFQDN = [System.Net.Dns]::GetHostByName(($env:computerName)).Hostname
  $SignatureAlgorithm = "SHA256"

  $name = New-Object -COM "X509Enrollment.CX500DistinguishedName.1"
  $name.Encode("CN=$SubjectName", 0)

  $key = New-Object -COM "X509Enrollment.CX509PrivateKey.1"
  $key.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
  $key.KeySpec = 1
  $key.Length = 4096
  $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
  $key.MachineContext = 1
  $key.Create()

  $serverauthoid = New-Object -COM "X509Enrollment.CObjectId.1"
  $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
  $ekuoids = New-Object -COM "X509Enrollment.CObjectIds.1"
  $ekuoids.Add($serverauthoid)
  $ekuext = New-Object -COM "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
  $ekuext.InitializeEncode($ekuoids)

  $cert = New-Object -COM "X509Enrollment.CX509CertificateRequestCertificate.1"
  $cert.InitializeFromPrivateKey(2, $key, "")
  $cert.Subject = $name
  $cert.Issuer = $cert.Subject
  $cert.NotBefore = (Get-Date).AddDays(-1)
  $cert.NotAfter = $cert.NotBefore.AddDays($ValidDays)

  $SigOID = New-Object -ComObject X509Enrollment.CObjectId
  $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)

  [string[]] $AlternativeName += $hostnonFQDN
  $AlternativeName += $hostFQDN
  $IAlternativeNames = New-Object -ComObject X509Enrollment.CAlternativeNames

  foreach ($AN in $AlternativeName) {
    $AltName = New-Object -ComObject X509Enrollment.CAlternativeName
    $AltName.InitializeFromString(0x3, $AN)
    $IAlternativeNames.Add($AltName)
  }

  $SubjectAlternativeName = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
  $SubjectAlternativeName.InitializeEncode($IAlternativeNames)

  [String[]]$KeyUsage = ("DigitalSignature", "KeyEncipherment")
  $KeyUsageObj = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
  $KeyUsageObj.InitializeEncode([int][Security.Cryptography.X509Certificates.X509KeyUsageFlags]($KeyUsage))
  $KeyUsageObj.Critical = $true

  $cert.X509Extensions.Add($KeyUsageObj)
  $cert.X509Extensions.Add($ekuext)
  $cert.SignatureInformation.HashAlgorithm = $SigOID
  $CERT.X509Extensions.Add($SubjectAlternativeName)
  $cert.Encode()

  $enrollment = New-Object -COM "X509Enrollment.CX509Enrollment.1"
  $enrollment.InitializeFromRequest($cert)
  $certdata = $enrollment.CreateRequest(0)
  $enrollment.InstallResponse(2, $certdata, 0, "")

  # extract/return the thumbprint from the generated cert
  $parsed_cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
  $parsed_cert.Import([System.Text.Encoding]::UTF8.GetBytes($certdata))

  return $parsed_cert.Thumbprint
}

Function Enable-GlobalHttpFirewallAccess {
  Write-Verbose "Forcing global HTTP firewall access"
  # this is a fairly naive implementation; could be more sophisticated about rule matching/collapsing
  $fw = New-Object -ComObject HNetCfg.FWPolicy2

  # try to find/enable the default rule first
  $add_rule = $false
  $matching_rules = $fw.Rules | Where-Object { $_.Name -eq "Windows Remote Management (HTTP-In)" }
  $rule = $null
  If ($matching_rules) {
    If ($matching_rules -isnot [Array]) {
      Write-Verbose "Editing existing single HTTP firewall rule"
      $rule = $matching_rules
    }
    Else {
      # try to find one with the All or Public profile first
      Write-Verbose "Found multiple existing HTTP firewall rules..."
      $rule = $matching_rules | ForEach-Object { $_.Profiles -band 4 }[0]

      If (-not $rule -or $rule -is [Array]) {
        Write-Verbose "Editing an arbitrary single HTTP firewall rule (multiple existed)"
        # oh well, just pick the first one
        $rule = $matching_rules[0]
      }
    }
  }

  If (-not $rule) {
    Write-Verbose "Creating a new HTTP firewall rule"
    $rule = New-Object -ComObject HNetCfg.FWRule
    $rule.Name = "Windows Remote Management (HTTP-In)"
    $rule.Description = "Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]"
    $add_rule = $true
  }

  $rule.Profiles = 0x7FFFFFFF
  $rule.Protocol = 6
  $rule.LocalPorts = 5985
  $rule.RemotePorts = "*"
  $rule.LocalAddresses = "*"
  $rule.RemoteAddresses = "*"
  $rule.Enabled = $true
  $rule.Direction = 1
  $rule.Action = 1
  $rule.Grouping = "Windows Remote Management"

  If ($add_rule) {
    $fw.Rules.Add($rule)
  }

  Write-Verbose "HTTP firewall rule $($rule.Name) updated"
}

#-----------------------------------------------------------[Start script]------------------------------------------------------------
# Elevating to admin
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  # Relaunch as an elevated process:
  Start-Process powershell.exe "-File", ('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}


Clear-Host

Write-Host -ForegroundColor White "###########################"
Write-Host -ForegroundColor Blue "### Start WinBootstrap ###"
Write-Host -ForegroundColor Red "###########################"

Write-Host "Pleas wait script..."

$(

  ### Custom block start

  ##### Definition ######

  $activeMAC = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Get-NetAdapter).MacAddress

  ######### Start Functions #########
  Write-Host "Set Set-ExecutionPilicy"
  Powershell Set-ExecutionPolicy Bypass -Force

  Disable-ComplexPassword
  Disable-Firewall
  Disable-Defender
  New-LocalAdmin -username $username -password $password
  Hide-User -username $username
  Set-NetworksAsPrivate
  Enable-RDP
  Enable-SNMP -CommString $ROCommuniti -SNMPManager $SNMPManager
  Set-HostnameByMAC -mac $activeMAC


  ### Custom block end
  # Configure a Windows host for remote management with Ansible
  # Fork https://github.com/ansible/ansible/raw/devel/examples/scripts/ConfigureRemotingForAnsible.ps1

  Write-Host "#---------------------------#"
  Write-Host "ConfigureRemotingForAnsible.ps1"
  Write-Host "#---------------------------#"

  # Setup error handling.
  Trap {
    $_
    Exit 1
  }
  $ErrorActionPreference = "Stop"

  # Get the ID and security principal of the current user account
  $myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

  # Get the security principal for the Administrator role
  $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

  # Check to see if we are currently running "as Administrator"
  if (-Not $myWindowsPrincipal.IsInRole($adminRole)) {
    Write-Output "ERROR: You need elevated Administrator privileges in order to run this script."
    Write-Output "       Start Windows PowerShell by using the Run as Administrator option."
    Exit 2
  }

  $EventSource = $MyInvocation.MyCommand.Name
  If (-Not $EventSource) {
    $EventSource = "Powershell CLI"
  }

  If ([System.Diagnostics.EventLog]::Exists('Application') -eq $False -or [System.Diagnostics.EventLog]::SourceExists($EventSource) -eq $False) {
    New-EventLog -LogName Application -Source $EventSource
  }

  # Detect PowerShell version.
  If ($PSVersionTable.PSVersion.Major -lt 3) {
    Write-Log "PowerShell version 3 or higher is required."
    Throw "PowerShell version 3 or higher is required."
  }

  # Find and start the WinRM service.
  Write-Verbose "Verifying WinRM service."
  If (!(Get-Service "WinRM")) {
    Write-Log "Unable to find the WinRM service."
    Throw "Unable to find the WinRM service."
  }
  ElseIf ((Get-Service "WinRM").Status -ne "Running") {
    Write-Verbose "Setting WinRM service to start automatically on boot."
    Set-Service -Name "WinRM" -StartupType Automatic
    Write-Log "Set WinRM service to start automatically on boot."
    Write-Verbose "Starting WinRM service."
    Start-Service -Name "WinRM" -ErrorAction Stop
    Write-Log "Started WinRM service."

  }

  # WinRM should be running; check that we have a PS session config.
  If (!(Get-PSSessionConfiguration -Verbose:$false) -or (!(Get-ChildItem WSMan:\localhost\Listener))) {
    If ($SkipNetworkProfileCheck) {
      Write-Verbose "Enabling PS Remoting without checking Network profile."
      Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop
      Write-Log "Enabled PS Remoting without checking Network profile."
    }
    Else {
      Write-Verbose "Enabling PS Remoting."
      Enable-PSRemoting -Force -ErrorAction Stop
      Write-Log "Enabled PS Remoting."
    }
  }
  Else {
    Write-Verbose "PS Remoting is already enabled."
  }

  # Ensure LocalAccountTokenFilterPolicy is set to 1
  # https://github.com/ansible/ansible/issues/42978
  $token_path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
  $token_prop_name = "LocalAccountTokenFilterPolicy"
  $token_key = Get-Item -Path $token_path
  $token_value = $token_key.GetValue($token_prop_name, $null)
  if ($token_value -ne 1) {
    Write-Verbose "Setting LocalAccountTOkenFilterPolicy to 1"
    if ($null -ne $token_value) {
      Remove-ItemProperty -Path $token_path -Name $token_prop_name
    }
    New-ItemProperty -Path $token_path -Name $token_prop_name -Value 1 -PropertyType DWORD > $null
  }

  # Make sure there is a SSL listener.
  $listeners = Get-ChildItem WSMan:\localhost\Listener
  If (!($listeners | Where-Object { $_.Keys -like "TRANSPORT=HTTPS" })) {
    # We cannot use New-SelfSignedCertificate on 2012R2 and earlier
    $thumbprint = New-LegacySelfSignedCert -SubjectName $SubjectName -ValidDays $CertValidityDays
    Write-HostLog "Self-signed SSL certificate generated; thumbprint: $thumbprint"

    # Create the hashtables of settings to be used.
    $valueset = @{
      Hostname              = $SubjectName
      CertificateThumbprint = $thumbprint
    }

    $selectorset = @{
      Transport = "HTTPS"
      Address   = "*"
    }

    Write-Verbose "Enabling SSL listener."
    New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
    Write-Log "Enabled SSL listener."
  }
  Else {
    Write-Verbose "SSL listener is already active."

    # Force a new SSL cert on Listener if the $ForceNewSSLCert
    If ($ForceNewSSLCert) {

      # We cannot use New-SelfSignedCertificate on 2012R2 and earlier
      $thumbprint = New-LegacySelfSignedCert -SubjectName $SubjectName -ValidDays $CertValidityDays
      Write-HostLog "Self-signed SSL certificate generated; thumbprint: $thumbprint"

      $valueset = @{
        CertificateThumbprint = $thumbprint
        Hostname              = $SubjectName
      }

      # Delete the listener for SSL
      $selectorset = @{
        Address   = "*"
        Transport = "HTTPS"
      }
      Remove-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset

      # Add new Listener with new SSL cert
      New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
    }
  }

  # Check for basic authentication.
  $basicAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object { $_.Name -eq "Basic" }

  If ($DisableBasicAuth) {
    If (($basicAuthSetting.Value) -eq $true) {
      Write-Verbose "Disabling basic auth support."
      Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $false
      Write-Log "Disabled basic auth support."
    }
    Else {
      Write-Verbose "Basic auth is already disabled."
    }
  }
  Else {
    If (($basicAuthSetting.Value) -eq $false) {
      Write-Verbose "Enabling basic auth support."
      Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
      Write-Log "Enabled basic auth support."
    }
    Else {
      Write-Verbose "Basic auth is already enabled."
    }
  }

  # If EnableCredSSP if set to true
  If ($EnableCredSSP) {
    # Check for CredSSP authentication
    $credsspAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where-Object { $_.Name -eq "CredSSP" }
    If (($credsspAuthSetting.Value) -eq $false) {
      Write-Verbose "Enabling CredSSP auth support."
      Enable-WSManCredSSP -role server -Force
      Write-Log "Enabled CredSSP auth support."
    }
  }

  If ($GlobalHttpFirewallAccess) {
    Enable-GlobalHttpFirewallAccess
  }

  # Configure firewall to allow WinRM HTTPS connections.
  $fwtest1 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS"
  $fwtest2 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS" profile=any
  If ($fwtest1.count -lt 5) {
    Write-Verbose "Adding firewall rule to allow WinRM HTTPS."
    netsh advfirewall firewall add rule profile=any name="Allow WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow
    Write-Log "Added firewall rule to allow WinRM HTTPS."
  }
  ElseIf (($fwtest1.count -ge 5) -and ($fwtest2.count -lt 5)) {
    Write-Verbose "Updating firewall rule to allow WinRM HTTPS for any profile."
    netsh advfirewall firewall set rule name="Allow WinRM HTTPS" new profile=any
    Write-Log "Updated firewall rule to allow WinRM HTTPS for any profile."
  }
  Else {
    Write-Verbose "Firewall rule already exists to allow WinRM HTTPS."
  }

  # Test a remoting connection to localhost, which should work.
  $httpResult = Invoke-Command -ComputerName "localhost" -ScriptBlock { $env:COMPUTERNAME } -ErrorVariable httpError -ErrorAction SilentlyContinue
  $httpsOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

  $httpsResult = New-PSSession -UseSSL -ComputerName "localhost" -SessionOption $httpsOptions -ErrorVariable httpsError -ErrorAction SilentlyContinue

  If ($httpResult -and $httpsResult) {
    Write-Verbose "HTTP: Enabled | HTTPS: Enabled"
  }
  ElseIf ($httpsResult -and !$httpResult) {
    Write-Verbose "HTTP: Disabled | HTTPS: Enabled"
  }
  ElseIf ($httpResult -and !$httpsResult) {
    Write-Verbose "HTTP: Enabled | HTTPS: Disabled"
  }
  Else {
    Write-Log "Unable to establish an HTTP or HTTPS remoting session."
    Throw "Unable to establish an HTTP or HTTPS remoting session."
  }
  Write-VerboseLog "PS Remoting has been successfully configured for Ansible."

) *>&1 > $logFile

Read-Host -Prompt "Finish! Log file saved in $logFile"
