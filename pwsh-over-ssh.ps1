[CmdletBinding()]
param(
  [Int]$Port,
  [Boolean]$UpgradeSSH,
  [Boolean]$UpgradePwsh
);

if (!([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
  throw "You must be running as an administrator, please restart as administrator.";
}

#region definitions

$FW_RULE_DISPLAY_NAME = "OpenSSH Server Access";
$FW_RULE_NAME = "SSHd-In";
$FW_RULE_DESCRIPTION = "Allow access to the OpenSSH server service.";

$OPENSSH_USERS_GROUP = "OpenSSHUsers";
$OPENSSH_USERS_GROUP_DESC = "Permit SSH to this computer";

$OPENSSH_URL = 'https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.5.0.0p1-Beta/OpenSSH-Win64-v9.5.0.0.msi';
$OPENSSH_VER = '9.5.0.0';
$PWSH_URL = 'https://github.com/PowerShell/PowerShell/releases/download/v7.4.1/PowerShell-7.4.1-win-x64.msi';
$PWSH_VER = [Version]'7.4.1';

Function Add-NtfsAce {
  [CmdletBinding()]param(
    [Parameter(Mandatory=$true)][String]$Path,
    [Parameter(Mandatory=$true)][String]$Account,
    [Parameter(Mandatory=$true)][ValidateSet('FullControl','Modify','Read','ReadAndExecute','Write')]$AccessRight,
    [Parameter(Mandatory=$false)][ValidateSet('Allow','Deny')][String]$AccessType = 'Allow'
  );

  $fullPath = Convert-Path -Path $Path;

  if (-not (Test-Path -Path "$($fullPath)" -ErrorAction SilentlyContinue)) {
    throw "Get-NtfsAce: The path '$($fullPath) does not exist.";
  }

  $acl = Get-Acl -Path "$($fullPath)";
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($Account,$AccessRight,$AccessType));
  if (-not $?) {
    throw "Add-NtfsAce: Error adding access rule '$($AccessType) $($Account) $($AccessRight)' to '$($fullPath)'";
  }

  Set-Acl -Path $fullPath -AclObject $acl;
}

Function AddTo-SystemPathEnv {
  param([String]$Path);

  $pathVar = @();
  $pathVar += [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine) -split ';';
  $isInPath = $false;
  foreach ($dir in $pathVar) {
    if ($dir.ToLower() -like $Path.ToLower() -or "$($dir.ToLower())\" -like "$($Path.ToLower())") {
      $isInPath = $true;
      break;
    }
  }

  if (-not ($isInPath)) {
    $pathVar += $Path;
    [System.Environment]::SetEnvironmentVariable('PATH',$($pathVar -join ';'),[System.EnvironmentVariableTarget]::Machine);
  }

  if (-not ($env:PATH -split ';' | Where-Object -FilterScript { $_ -like $Path -or $_ -like "$($Path)\" })) {
    $env:PATH = "$($env:PATH);$($Path)";
  }
}

Function Get-NtfsAce {
  [CmdletBinding()]param(
    [Parameter(Mandatory=$true, Position=0)][String]$Path,
    [Parameter(Mandatory=$false)][String]$Account,
    [Parameter(Mandatory=$false)][Switch]$ExcludeInherited
  );
  $fullPath = Convert-Path -Path $Path;

  if (-not (Test-Path -Path "$($fullPath)" -ErrorAction SilentlyContinue)) {
    throw "Get-NtfsAce: The path '$($fullPath) does not exist.";
  }

  $ACEs = Get-Acl -Path "$($fullPath)" | Select-Object -ExpandProperty Access;
  Remove-Variable -Name fullPath -ErrorAction SilentlyContinue;

  if ($Account) {
    $ACEs = $ACEs | Where-Object -FilterScript { $_.IdentityReference -like "$($Account)" }
  }

  if ($ExcludeInherited.IsPresent) {
    return $ACEs | Where-Object -FilterScript { $_.IsInherited -eq $false }
  }

  return $ACEs;

}

Function Get-PwshExeFile {
  param([Switch]$All);
  $pwshExeFiles = @();

  $pwshExeFiles += $env:PATH -split ";" |
      Foreach-Object -Process { Get-Item -Path "$($_ -replace '\\$','')\pwsh.exe" -ErrorAction SilentlyContinue } |
      Select-Object -Property *,@{n='Version';e={[Version]$_.VersionInfo.FileVersion}}

  if ($pwshExeFiles.Count -lt 1) {
    $pwshExeFiles += Get-ChildItem -Path "$($env:ProgramData)\Microsoft\Windows\Start Menu" -Filter "PowerShell*.lnk" |
        Where-Object -FilterScript { $_.Name -notmatch 'Windows' } |
        Foreach-Object -Process { (New-Object -ComObject WScript.Shell).CreateShortcut($_.FullName).TargetPath;} |
        Foreach-Object -Process { Get-Item -Path $_ -ErrorAction SilentlyContinue } |
        Select-Object -Property *,@{n='Version';e={[Version]$_.VersionInfo.FileVersion}}
  }

  if ($pwshExeFiles.Count -lt 1) {
    $pwshExeFiles += Get-ChildItem -Path "$($env:ProgramFiles)" -Filter "pwsh.exe" -Recurse -ErrorAction SilentlyContinue |
        Select-Object -Property *,@{n='Version';e={[Version]$_.VersionInfo.FileVersion}}
  }

  if ($All.IsPresent) {
    return $pwshExeFiles | Sort-Object -Descending -Property Version;
  } else {
    return $pwshExeFiles | Sort-Object -Descending -Property Version | Select-Object -First 1;
  }
}

Function Get-RandomChars {
  param([Int]$Count);
  $characters = 65..90 | Foreach-Object -Process { [char]$_ }
  $characters += @(0,1,2,3,4,5,6,7,8,9);
  ($characters | Get-Random -Count $Count) -join '';
  Remove-Variable -Name characters -ErrorAction SilentlyContinue;
}

Function Remove-AclInheritance {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][String]$Path);

  $fullPath = Convert-Path -Path $Path;

  if (-not (Test-Path -Path "$($fullPath)" -ErrorAction SilentlyContinue)) {
    throw "Remove-AclInheritance: The path '$($fullPath) does not exist.";
  }

  $acl = Get-Acl -Path $fullPath;
  $acl.SetAccessRuleProtection($true, $false);
  Set-Acl -Path $fullPath -AclObject $acl;
}

Function RemoveFrom-PathEnv {
  param([String]$Path);
  $sysPathVar = @();
  $sysPathVar += [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine) -split ';' |
      Where-Object -FilterScript { $_ -notlike "$($Path)" -and $_ -notlike "$($Path)\" }
  [System.Environment]::SetEnvironmentVariable('PATH', "$($sysPathVar -join ';')", [System.EnvironmentVariableTarget]::Machine);
  
  $userPathVar = @();
  $userPathVar += [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::User) -split ';' |
      Where-Object -FilterScript { $_ -notlike "$($Path)" -and $_ -notlike "$($Path)\" }
  [System.Environment]::SetEnvironmentVariable('PATH', "$($userPathVar -join ';')", [System.EnvironmentVariableTarget]::User);
}

#region validate arguments

if ($Port) {
  if ($Port -lt 1) {
    throw "OpenSSH Port must be greater than 0";
  }
  if ($Port -gt 65535) {
    throw "OpenSSH Port must be less than 65535";
  }
  $openSSHPort = $Port;
} else {
  $openSSHPort = -1;
}

while ($openSSHPort -eq -1) {
  $openSSHPort = Invoke-Command -ScriptBlock {
    $response = Read-Host -Prompt "OpenSSH Port (1-65535) [22]";
    $r = $response.Trim();
    Remove-Variable -Name response -ErrorAction SilentlyContinue;
    if ($r -eq '') {
      return 22;
    }

    if ($r -notmatch '^[0-9]+$') {
      Write-Host "OpenSSH Port must be a number" -ForegroundColor Red;
      return -1;
    }

    $n = [Int]::Parse($r);
    if ($n -lt 1) {
      Write-Host "OpenSSH Port must be greater than 0" -ForegroundColor Red;
      return -1;
    }

    if ($n -gt 65535) {
      Write-Host "OpenSSH Port must be less than 65535" -ForegroundColor Red;
      return -1;
    }

    return $n;
  }
}

if ($PSBoundParameters.Keys -notcontains 'UpgradeSSH') {
  $validAnswer = $false;
  while (-not $validAnswer) {
    Write-Output "";
    $answer = Read-Host -Prompt "If OpenSSH version is lower than $($OPENSSH_VER), `nUpgrade (Blank = yes)? [Y/n]";
    Switch -Regex ($answer) {
      "^([ \t]*|y(|es)|t(|rue))$" {
        $UpgradeSSH = $true;
        $validAnswer = $true;
      }
      "^(n(|o)|f(|alse))$" {
        $UpgradeSSH = $false;
        $validAnswer = $true;
      }
      default {
        Write-Output "'$($answer)' not valid. Please answer yes or no (or blank for yes)."
      }
    }
  }
  Remove-Variable -Name validAnswer -ErrorAction SilentlyContinue;
}

if ($PSBoundParameters.Keys -notcontains 'UpgradePwsh') {
  $validAnswer = $false;
  while (-not $validAnswer) {
    Write-Output "";
    $answer = Read-Host -Prompt "If PowerShell Core version is lower than $($PWSH_VER), `nUpgrade (Blank = yes)? [Y/n]";
    Switch -Regex ($answer) {
      "^([ \t]*|y(|es)|t(|rue))$" {
        $UpgradePwsh = $true;
        $validAnswer = $true;
      }
      "^(n(|o)|f(|alse))$" {
        $UpgradePwsh = $false;
        $validAnswer = $true;
      }
      default {
        Write-Output "'$($answer)' not valid. Please answer yes or no (or blank for yes)."
      }
    }
  }
  Remove-Variable -Name validAnswer -ErrorAction SilentlyContinue;
}

#endregion

#region Prereq's

[System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.SecurityProtocolType]::Tls12 -bor
    [System.Net.SecurityProtocolType]::Tls13;

Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force -Confirm:$false;

#endregion

#region OpenSSH Install
$sshdExistingVer = [Version]'0.0.0.0';
if (Get-Service -Name sshd -ErrorAction SilentlyContinue) {
  Get-CimInstance -ClassName Win32_Service -Filter "Name = 'sshd'" | Foreach-Object -Process {
    $sshdExistingPath = $_.PathName -replace '"','';
    $sshdExistingExe = Get-Item -Path $sshdExistingPath;
    Remove-Variable -Name $sshdExistingPath -ErrorAction SilentlyContinue;
    $sshdExistingVer = [Version]$sshdExistingExe.VersionInfo.FileVersion;
  }
}

if (Get-Command -Name Get-WindowsCapability -ErrorAction SilentlyContinue) {
  $winCapOpenSSH = Get-WindowsCapability -Online -Name "*ssh*" -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*Server*' };
  if ($winCapOpenSSH) {
    $canInstallSSHViaWinCap = $true;
    $isWinCapOpenSSHInstalled = $winCapOpenSSH.State -like 'Installed';
  }
  Remove-Variable -Name winCapOpenSSH -ErrorAction SilentlyContinue;
}

if ($sshdExistingVer -lt $OPENSSH_VER -and $sshdExistingExe -and -not $canInstallSSHViaWinCap -and $UpgradeSSH) {
  $sshdUnInstallScript = "$($sshdExistingExe.DirectoryName)\uninstall-sshd.ps1";
  $sshdWmiApp = Get-CimInstance -ClassName Win32_Product -Filter "Name like '%OpenSSH%'" -ErrorAction SilentlyContinue;

  if ($sshdWmiApp) {
    Write-Output "Uninstalling OpenSSH version $($sshdExistingVer) using msiexec.exe";
    $randomDigits = Get-RandomChars -Count 5;
    $stdErrPath = "$env:TEMP\stdErr.$($randomDigits).txt";
    $stdOutPath = "$env:TEMP\stdOut.$($randomDigits).txt";
    Remove-Variable -Name randomDigits -ErrorAction SilentlyContinue;
    $sshdUninstallMsiProc = Start-Process -FilePath msiexec.exe `
        -ArgumentList '/x',$sshdWmiApp.IdentifyingNumber,"/qn" `
        -Verb RunAs `
        -Wait `
        -PassThru

    if (Get-Service -Name sshd -ErrorAction SilentlyContinue) {
      throw "Failed to uninstall OpenSSH Win64. MsiExec exit code = $($sshdUninstallMsiProc.ExitCode).";
    }

    Write-Output "Ensuring that the existing OpenSSH directory is not in the PATH environment variable";
    RemoveFrom-PathEnv -Path "$($sshdExistingExe.DirectoryName)";

    $sshdExistingExe = $null;

    Remove-Variable -Name sshdUninstallMsiProc -ErrorAction SilentlyContinue;
  } elseif (Test-Path -Path "$($sshdUnInstallScript)" -ErrorAction SilentlyContinue) {
    Write-Output "Uninstalling OpenSSH version $($sshdExistingVer) using uninstall script 'uninstall-sshd.ps1'";
    Unblock-File -Path "$($sshdUnInstallScript)" -Confirm:$false;
    $sshdUninstallScriptOut = & $sshdUnInstallScript 2>&1;
    $sshdUninstallScriptExit = $LASTEXITCODE;

    if (Get-Service -Name sshd -ErrorAction SilentlyContinue) {
      throw "Failed to uninstall OpenSSH Win64. Script exit code = $($sshdUninstallScriptExit). Script output:`n$($sshdUninstallScriptOut)";
    }

    Remove-Item -Path $sshdExistingExe.DirectoryName -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue;
    Write-Output "Ensuring that the existing OpenSSH directory is not in the PATH environment variable";
    RemoveFrom-PathEnv -Path "$($sshdExistingExe.DirectoryName)";
    
    $sshdExistingExe = $null;
    Remove-Variable -Name sshdUnInstallScriptOut,sshdUnInstallScriptExit  -ErrorAction SilentlyContinue;
  } else {
    Write-Output "Unable to determine how to uninstall sshd service. OpenSSH will not be upgraded.";
  }
  Remove-Variable -Name sshdUnInstallScript,sshdWmiApp -ErrorAction SilentlyContinue;
} elseif ($sshdExistingVer -lt $OPENSSH_VER -and $sshdExistingExe -and -not $canInstallSSHViaWinCap -and -not $UpgradeSSH) {
  Write-Output "OpenSSH server version $($sshdExistingVer) installed and not upgrading.";
}

if ($canInstallSSHViaWinCap -and $isWinCapOpenSSHInstalled) {
  Write-Output "OpenSSH server available from Windows Capabilities and already installed.";
} elseif ($canInstallSSHViaWinCap -and -not $isWinCapOpenSSHInstalled) {
  Write-Output "Adding OpenSSH Server using Windows capability.";
  Get-WindowsCapability -Name *ssh*server* -Online | Add-WindowsCapability -Online -ErrorAction Stop -Verbose;
} elseif (-not $sshdExistingExe) {
  $opensshMsiPath = "$env:TEMP\OpenSSH-Win64-v$($OPENSSH_VER).msi";
  if (Test-Path -Path "$($opensshMsiPath)" -ErrorAction SilentlyContinue) {
    Remove-Item -Path "$($opensshMsiPath)" -Force -Confirm:$false;
  }

  Write-Output "Downloading OpenSSH Server MSI installer.";
  [System.Net.WebClient]::new().DownloadFile($OPENSSH_URL,$opensshMsiPath);
  if (-not $?) {
    throw "Error downloading OpenSSH Server MSI installer.";
  }

  $randomDigits = Get-RandomChars -Count 5;
  $stdErrPath = "$env:TEMP\stdErr.$($randomDigits).txt";
  $stdOutPath = "$env:TEMP\stdOut.$($randomDigits).txt";
  Remove-Variable -Name randomDigits -ErrorAction SilentlyContinue;

  $sshdInstallStartProcArgs = @{
    'FilePath' = 'msiexec.exe';
    'ArgumentList' = @('/i',"`"$($opensshMsiPath)`"",'/qn');
    'NoNewWindow' = $null;
    'Wait' = $null;
    'PassThru' = $null;
    'RedirectStandardError' = "$($stdErrPath)";
    'RedirectStandardOut' = "$($stdOutPath)";
    'ErrorAction' = 'Stop'
  }
  Remove-Variable -Name opensshMsiPath -ErrorAction SilentlyContinue;

  Write-Output "Installing OpenSSH Server via MSI.";
  $sshdInstallProc = Start-Process @sshdInstallStartProcArgs;

  if (-not (Get-Service -Name sshd -ErrorAction SilentlyContinue)) {
    $stdErr = Get-Content -Path $stdErrPath -Raw;
    Remove-Item -Path $stdErrPath -Force -Confirm:$false -ErrorAction SilentlyContinue;
    $stdOut = Get-Content -Path $stdOutPath -Raw;
    Remove-Item -Path $stdOutPath -Force -Confirm:$false -ErrorAction SilentlyContinue;
    throw @"
Failed to uninstall OpenSSH Win64. Script exit code = $($sshdInstallProc.ExitCode)
* msiexec.exe StandardError:
$stdErr
* msiexec.exe StandardOut:
$stdOut
"@;
  }
  
  $sshdExePath = Get-CimInstance -ClassName Win32_Service -Filter "Name = 'sshd'" |
      Foreach-Object -Process { $_.PathName -replace '"',''; }
  AddTo-SystemPathEnv -Path "$(Split-Path -Path $sshdExePath -Parent)";
  Remove-Variable -Name sshdExePath -ErrorAction SilentlyContinue;

  Remove-Variable -Name sshdInstallProc,sshdInstallStartProcArgs,stdErrPath,stdOutPath -ErrorAction SilentlyContinue;
} else {
  Write-Output "OpenSSH server already installed.";
}
Remove-Variable -Name sshdExistingVer,sshdExistingExe,isWinCapOpenSSHInstalled,canInstallSSHViaWinCap -ErrorAction SilentlyContinue;

Get-Service -Name sshd,ssh-agent | Set-Service -StartupType Automatic;
Get-Service -Name sshd,ssh-agent | Where-Object -FilterScript { $_.Status -eq 'Stopped' } | Start-Service;
Get-Service -Name sshd,ssh-agent | Stop-Service;

$sshdHostKeyFiles = @(
  'ssh_host_dsa_key',
  'ssh_host_ecdsa_key',
  'ssh_host_ed25519_key',
  'ssh_host_rsa_key'
);

foreach ($hostKeyFile in $sshdHostKeyFiles) {
  $hostKeyFilePath = "$("$($env:ProgramData)\ssh\$($hostKeyFile)")";

  if (-not (Test-Path -Path "$($hostKeyFilePath)" -ErrorAction SilentlyContinue)) {
    ssh-keygen -A
  }

  foreach ($account in @('NT AUTHORITY\SYSTEM','BUILTIN\ADMINISTRATOR')) {
    if (-not (Get-NTFSAce -Path "$($hostKeyFilePath)" -Account 'NT AUTHORITY\SYSTEM' -ExcludeInherited -ErrorAction SilentlyContinue)) {
      Write-Output "Explicity granting FullControl for '$($account)' on '$($hostKeyFilePath)";
      Add-NtfsAce -Path "$($hostKeyFilePath)" -Account "$($account)" -AccessRights FullControl -AccessType Allow;
    }
  }

  Write-Output "Ensuring inheritance on '$($hostKeyFilePath)' is disabled.";
  Remove-AclInheritance -Path "$($hostKeyFilePath)";

  Remove-Variable -Name hostKeyFilePath -ErrorAction SilentlyContinue;
}
Remove-Variable -Name sshdHostKeyFiles -ErrorAction SilentlyContinue;

$adminAuthFile = "$($env:ProgramData)\ssh\administrators_authorized_keys";
if (-not (Test-Path -Path "$($adminAuthFile)" -ErrorAction SilentlyContinue)) {
  Write-Output "Creating empty administrators_authorized_keys file.";
  
  $auth_keys_encoding = New-Object System.Text.UTF8Encoding $False;
  [System.IO.File]::WriteAllLines("$($adminAuthFile)",@(),$auth_keys_encoding);
  
  Remove-Variable -Name auth_keys_encoding -ErrorAction SilentlyContinue;
}

foreach ($account in @('NT AUTHORITY\SYSTEM','BUILTIN\ADMINISTRATOR')) {
  if (-not (Get-NtfsAce -Path "$($adminAuthFile)" -Account 'NT AUTHORITY\SYSTEM' -ExcludeInherited -ErrorAction SilentlyContinue)) {
    Write-Output "Explicity granting FullControl for '$($account)' on '$($adminAuthFile)";
    Add-NtfsAce -Path "$($adminAuthFile)" -Account "$($account)" -AccessRights FullControl -AccessType Allow;
  }
}

Write-Output "Ensuring inheritance on '$($adminAuthFile)' is disabled.";
Remove-AclInheritance -Path "$($adminAuthFile)";

Remove-Variable -Name adminAuthFile -ErrorAction SilentlyContinue;

if (-not (Get-NetFirewallRule -Name "$($FW_RULE_NAME)" -ErrorAction SilentlyContinue)) {
  Write-Output "Adding Windows firewall rule";

  New-NetFirewallRule `
    -Name $FW_RULE_NAME `
    -DisplayName $FW_RULE_DISPLAY_NAME `
    -Description $FW_RULE_DESCRIPTION `
    -Group 'sshd' `
    -Enabled True `
    -Direction Inbound `
    -Profile Any `
    -Program $sshdExePath `
    -Confirm:$false
} else {
  Write-Output "Windows firewall rule for SSH already exists.";
}

#endregion

#region Install Powershell Core

$existingPwshExe = Get-PwshExeFile -All;
$existingPwshApp = Get-CimInstance -ClassName Win32_Product -Filter "Name like 'PowerShell%'" |
    Select-Object -Property @{n='Ver';e={[Version]$_.Version}} |
    Sort-Object -Property Ver -Descending|
    Select-Object -First 1;

if ($existingPwshExe -or $existingPwshApp) {
  if ($existingPwshApp) {
    $existingPwshVersion = $existingPwshApp.Ver;
  } else {
    $existingPwshVersion = $existingPwshExe.Version;
  }
  if ($existingPwshVersion -lt $PWSH_VER -and -not $UpgradePwsh) {
    Write-Output "PowerShell Core earlier version $($existingPwshExe.Version) installed which. Not upgrading.";
  } elseif ($existingPwshVersion -lt $PWSH_VER -and $UpgradePwsh) {

    if ($existingPwshApp) {
      
      Write-Output "Uninstalling PowerShell Core version $($existingPwshExe.Version) using msiexec.exe";
      $randomDigits = Get-RandomChars -Count 5;
      $stdErrPath = "$env:TEMP\stdErr.$($randomDigits).txt";
      $stdOutPath = "$env:TEMP\stdOut.$($randomDigits).txt";
      Remove-Variable -Name randomDigits -ErrorAction SilentlyContinue;
      $pwshUninstallMsiProc = Start-Process -FilePath msiexec.exe `
          -ArgumentList '/x',$existingPwshApp.IdentifyingNumber,"/qn" `
          -NoNewWindow `
          -Wait `
          -PassThru `
          -RedirectStandardError $stdErrPath `
          -RedirectStandardOutput $stdOutPath

      if ($pwshUninstallMsiProc.ExitCode -ne 0) {
        $stdErr = Get-Content -Path $stdErrPath -Raw;
        Remove-Item -Path $stdErrPath -Force -Confirm:$false -ErrorAction SilentlyContinue;
        $stdOut = Get-Content -Path $stdOutPath -Raw;
        Remove-Item -Path $stdOutPath -Force -Confirm:$false -ErrorAction SilentlyContinue;
        throw @"
Failed to uninstall PowerShell Core. MsiExec exit code = $($sshdUninstallMsiProc.ExitCode).
* msiexec.exe Standard Error:
$stdErr
* msiexec.exe Standard Out:
$stdOut
"@
      } 
    }

    $existingPwshExe | Foreach-Object -Process {
      RemoveFrom-PathEnv -Path "$($_.DirectoryName)";
    }
  
    $existingPwshExe = $null;
    $existingPwshApp = $null;
  }

} else {
  Write-Output "Unable to determine path to an existing PowerShell Core install. Assuming PowerShell Core is not installed.";
}

if (-not $existingPwshExe) {
  Write-Output "Downloading PowerShell Core version $($PWSH_VER) from '$($PWSH_URL)";
  $pwshDownloadPath = "$env:TEMP\PowerShell-$($PWSH_VER)-win-x64.msi";
  [System.Net.WebClient]::new().DownloadFile($PWSH_URL, $pwshDownloadPath);
  if (-not $?) {
    throw "Error downloading PowerShell.";
  }

  Write-Output "Installing PowerShell Core using msiexec.exe";
  $randomDigits = Get-RandomChars -Count 5;
  $stdErrPath = "$env:TEMP\stdErr.$($randomDigits).txt";
  $stdOutPath = "$env:TEMP\stdOut.$($randomDigits).txt";
  Remove-Variable -Name randomDigits -ErrorAction SilentlyContinue;
  $pwshMsiArgs = @(
    '/i', "`"$($pwshDownloadPath)`"",
    "/qn",
    "ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1",
    "ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=1",
    "ADD_PATH=1",
    "REGISTER_MANIFEST=1",
    "USE_MU=1",
    "ENABLE_MU=1"
  );
  $pwshInstallMsiProc = Start-Process -FilePath msiexec.exe `
      -ArgumentList $pwshMsiArgs `
      -NoNewWindow `
      -Wait `
      -PassThru `
      -RedirectStandardError $stdErrPath `
      -RedirectStandardOutput $stdOutPath;
    Remove-Variable -Name pwshMsiArgs -ErrorAction SilentlyContinue;

  if ($pwshInstallMsiProc.ExitCode -ne 0) {
    $stdErr = Get-Content -Path $stdErrPath -Raw;
    Remove-Item -Path $stdErrPath -Force -Confirm:$false -ErrorAction SilentlyContinue;
    $stdOut = Get-Content -Path $stdOutPath -Raw;
    Remove-Item -Path $stdOutPath -Force -Confirm:$false -ErrorAction SilentlyContinue;
    throw @"
Failed to install PowerShell Core. MsiExec exit code = $($sshdUninstallMsiProc.ExitCode).
* msiexec.exe Standard Error:
$stdErr
* msiexec.exe Standard Out:
$stdOut
"@
  }

  Remove-Item -Path $stdErrPath,$stdOutPath -Confirm:$false -Force -ErrorAction SilentlyContinue;
  Remove-Variable -Name pwshInstallMsiProc,stdErrPath,stdOutPath -ErrorAction SilentlyContinue;

  $pwshExeFile = Get-PwshExeFile;
  AddTo-SystemPathEnv -Path "$($pwshExeFile.DirectoryName)";

  Remove-Variable -Name existingPwshExe -ErrorAction SilentlyContinue;
} else {
  Write-Output "PowerShell Core already installed.";
  $pwshExeFile = $existingPwshExe | Select-Object -First 1;
}

#endregion

#region update sshd config

$pwshShortPath4sshd = (New-Object -ComObject Scripting.FileSystemObject).GetFile($pwshExeFile.FullName).ShortPath -replace '\\','/';

if (-not (net.exe LOCALGROUP | Select-String -SimpleMatch "$($OPENSSH_USERS_GROUP)")) {
  Write-Output "Adding local group '$($OPENSSH_USERS_GROUP)'";
  net LOCALGROUP "$($OPENSSH_USERS_GROUP)" /ADD /COMMENT:"$($OPENSSH_USERS_GROUP_DESC)";
  if (-not $?) {
    throw "Error adding group '$($OPENSSH_USERS_GROUP)";
  }
} else {
  Write-Output "Local group '$($OPENSSH_USERS_GROUP)' already exists.";
}

$listenAddrCommentLineNum = -1;
$listenAddrLineNum = -1;
$portCommentLineNum = -1;
$portNeedsUpdate = $true;
$allowGroupNeedsUpdate = $true;
$beforeMatchesLine = -1;

$newSshdConfig = @();
$i = 0;

Write-Output "Parsing existing sshd configuration file.";
foreach ($line in (Get-Content -Path "$($env:ProgramData)\ssh\sshd_config")) {

  if ($beforeMatchesLine -eq -1 -and $line -match "^[\s\t]*Match") {
    $beforeMatchesLine = $i - 1;
  }

  if ($beforeMatchesLine -eq -1) {

    if ($line -match '^[ \t]*Port') {
      $newSshdConfig += "Port $($Port)";
      $portNeedsUpdate = $false;
      $i++;
      continue;
    }

    if ($line -match '[ \t]*#[ \t]*Port') {
      $portCommentLineNum = $i;
      $newSshdConfig += $line;
      $i++;
      continue;
    }

    if ($line -match '^[ \t]*#[ \t]*ListenAddress') {
      $listenAddrCommentLineNum = $i;
      $newSshdConfig += $line;
      $i++;
      continue;
    }

    if ($line -match '^[ \t]*ListenAddress[ \t]+([0-9]{1,3}\.){3}[0-9]{1,3}:') {
      $listenMatches = [Regex]::Matches($line, '^([ \t]*ListenAddress[ \t]+([0-9]{1,3}\.){3}[0-9]{1,3}):');
      $newSshdConfig += "$($listenMatches.Groups[1]):$($Port)";
      $portNeedsUpdate = $false;
      Remove-Variable -Name listenMatches -ErrorAction SilentlyContinue;
      $i++;
      continue;
    }

    if ($line -match '^[\s\t]*ListenAddress[\s\t]+\[[0-9A-Fa-f:]+\]:') {
      if ($listenAddrLineNum -eq -1) {
        $listenAddrLineNum = $i;
      }
      $listenMatches = [Regex]::Matches($line, '([\s\t]*ListenAddress[\s\t]+)(\[[0-9A-Fa-f:]+\]):');
      $newSshdConfig += "$($listenMatches.Groups[1]) $($listenMatches.Groups[2]):$($Port)";
      $portNeedsUpdate = $false;
      Remove-Variable -Name listenMatches -ErrorAction SilentlyContinue;
      $i++;
      continue;
    }

    if ($line -match '^[\s\t]*[Ss]ubsystem[\s\t]+[Ss]ftp') {
      $newSshdConfig += $line;
      $newSshdConfig += "Subsystem`tpowershell`t$pwshShortPath4sshd -sshs -NoLogo";
      $i+=2;
      continue;
    }

    if ($line -match '^[\s\t]*[Ss]ubsystem[\s\t]+[Pp]ower[Ss]hell') {
      continue;
    }

    if ($line -match '^[ \t]*AllowGroups') {
      $allowedGroups = @();
      $allowedGroups += ($line -replace "^[ \t]*AllowGroups[ \t]+") -split '[ \t]+';
      if ($allowedGroups -notcontains 'Administrators') {
        $allowedGroups += "Administrators";
      }
      if ($allowedGroups -notcontains "$($OPENSSH_USERS_GROUP)") {
        $allowedGroups += $OPENSSH_USERS_GROUP;
      }

      $newSshdConfig += "AllowGroups $($allowedGroups -join ' ')";
      $allowGroupNeedsUpdate = $false;
      $i++;
      continue;
    }
  }

  $newSshdConfig += $line;
  $i++;
}

if ($portNeedsUpdate) {
  if ($portCommentLineNum -ne -1) {
    $updatedSshdConfig = $newSshdConfig[0..$portCommentLineNum] + "Port $($Port)" + $newSshdConfig[$($portCommentLineNum + 1)..$($newSshdConfig.Length-1)];
    $newSshdConfig = $updatedSshdConfig;
    Remove-Variable -Name updatedSshdConfig -ErrorAction SilentlyContinue;
  } elseif ($listenAddrCommentLineNum -ne -1) {
    $updatedSshdConfig = $newSshdConfig[0..$($listenAddrCommentLineNum-1)] + "Port $($Port)" + $newSshdConfig[$listenAddrCommentLineNum..$($newSshdConfig.Length-1)];
    $newSshdConfig = $updatedSshdConfig;
    Remove-Variable -Name updatedSshdConfig -ErrorAction SilentlyContinue;
  } elseif ($beforeMatchesLine -ne -1) {
    $updatedSshdConfig = $newSshdConfig[0..$beforeMatchesLine] + "Port $($Port)" + $newSshdConfig[$($beforeMatchesLine+1)..$($newSshdConfig.Length-1)];
    $newSshdConfig = $updatedSshdConfig;
    Remove-Variable -Name updatedSshdConfig -ErrorAction SilentlyContinue;
  } else {
    $newSshdConfig += "Port $($Port)";
  }

  if ($beforeMatchesLine -ne -1) {
    $beforeMatchesLine++;
  }
}

if ($allowGroupNeedsUpdate) {
  if ($beforeMatchesLine -ne -1) {
    $updatedSshdConfig = $newSshdConfig[0..$beforeMatchesLine] + "AllowGroups Administrators $($OPENSSH_USERS_GROUP)" + $newSshdConfig[$($beforeMatchesLine+1)..$($newSshdConfig.Length-1)];
    $newSshdConfig = $updatedSshdConfig;
    Remove-Variable -Name updatedSshdConfig -ErrorAction SilentlyContinue;
  } else {
    $newSshdConfig += "AllowGroups Administrators $($OPENSSH_USERS_GROUP)";
  }
}
Remove-Variable -Name listenAddrCommentLineNum,listenAddrLineNum,portCommentLineNum,portNeedsUpdate,beforeMatchesLine -ErrorAction SilentlyContinue;

Write-Output "Writing updated sshd configuration file";
$encoding = New-Object System.Text.UTF8Encoding $False;
[System.IO.File]::WriteAllLines("$($env:ProgramData)\ssh\sshd_config",$newSshdConfig,$encoding);
Remove-Variable -Name encoding -ErrorAction SilentlyContinue;

Restart-Service -Name sshd -ErrorAction Stop;
#endregion