# ListAvailablePipesOnRemoteMachine

# File name          : ListAvailablePipesOnRemoteMachine.ps1
# Author             : Podalirius (@podalirius_)
# Date created       : 20 July 2022


Param (
    [parameter(Mandatory=$false)][string]$TargetIP = $null,
    [parameter(Mandatory=$false)][string]$Username = $null,
    [parameter(Mandatory=$false)][string]$Password = $null,
    [parameter(Mandatory=$false)][string]$Domain = $null,
    [parameter(Mandatory=$false)][string]$LogFile = $null,
    [parameter(Mandatory=$false)][int]$Delay = 1,
    [parameter(Mandatory=$false)][switch]$Help,
    [parameter(Mandatory=$false)][switch]$Live,
    [parameter(Mandatory=$false)][switch]$Local
)


Function ShowHelp {
    Begin
    {
        Write-Host "Required arguments:"
        Write-Host "  -TargetIP   : List SMB pipes on a remote machine."
        Write-Host "  or"
        Write-Host "  -Local      : List SMB pipes on the local machine."
        Write-Host ""
        Write-Host "Optional arguments:"
        Write-Host "  -Help       : Displays this help message"
        Write-Host "  -Domain     : Target domain to authenticate to."
        Write-Host "  -Username   : User to authenticate as."
        Write-Host "  -Password   : Password for authentication."
        Write-Host "  -LogFile    : Log file to save output to."
        Write-Host "  -Live       : List SMB pipes in live mode. (default: False)"
        Write-Host "  -Delay      : Delay between two queries in seconds (default: 1)."
        Write-Host ""
    }
}


Write-Host "ListAvailablePipesOnRemoteMachine v1.1 - by Remi GASCOU (Podalirius)"
Write-Host ""

If ($Help) {
    ShowHelp
    exit 0
}
If ((!$TargetIP) -And (!$Local)) {
    ShowHelp
    Write-Host "Either -TargetIP or -Local option is required."
    exit 0
}

If ($LogFile.Length -ne 0) {
    # Init log file
    $Stream = [System.IO.StreamWriter]::new($LogFile)
    $Stream.Close()
}

if ($Delay) {
    $DelayInSeconds = $Delay;
} else {
    $DelayInSeconds = 1;
}

#===============================================================================

if ($Live) {
    # Live mode
    if ($Local) {
        # Listing Local SMB pipes in live mode
        Write-Host "[>] Listing open SMB pipes on the local machine in live mode ... "
        Write-Host ""

        [System.Collections.ArrayList]$allpipes = @();
        [System.Collections.ArrayList]$allpipes_before = @();
        Foreach ($pipe in (get-childitem \\.\pipe\ | sort {$_.FullName})) {
            $allpipes.add(('\\PIPE\{0}' -f $pipe.Name)) | Out-Null;
            $allpipes_before.add(('\\PIPE\{0}' -f $pipe.Name)) | Out-Null;
        }

        $dateprompt = ("[{0}]" -f (Get-Date -Format "yyyy/MM./dd hh:mm:ss"));

        Write-Verbose ("Waiting {0} second." -f $DelayInSeconds);
        Start-Sleep -Seconds $DelayInSeconds
       
        While ($true) {
            # Update pipes
            $allpipes.clear();
            Foreach ($pipe in (get-childitem \\.\pipe\ | sort {$_.Name})) {
                $allpipes.add(('\\PIPE\{0}' -f $pipe.Name)) | Out-Null;
            }

            $dateprompt = ("[{0}]" -f (Get-Date -Format "yyyy/MM/dd hh:mm:ss"));

            Foreach ($pipe in $allpipes) {
                if ($allpipes_before -contains $pipe){
                    # Already known
                    # Write-Host "Already known"
                } else {
                    # Write-Host "Not known"
                    Write-Host ("{0} Pipe '{1}' was created." -f $dateprompt, $pipe);
                }
            };

           Foreach ($pipe in $allpipes_before) {
                if ($allpipes -contains $pipe){
                    # Already known
                    # Write-Host "Already known"
                } else {
                    # Write-Host "Not known"
                    Write-Host ("{0} Pipe '{1}' was deleted." -f $dateprompt, $pipe);
                }
            };

            $allpipes_before.clear();
            Foreach ($pipe in $allpipes) {
                $allpipes_before.add($pipe) | Out-Null;
            }
            Write-Verbose ("Waiting {0} second." -f $DelayInSeconds);
            Start-Sleep -Seconds $DelayInSeconds
        }

        Write-Host ("[+] Found {0} pipes." -f $allpipes.length)

    } else {
        # Listing Remote SMB pipes in live mode
        Write-Host "[>] Listing open SMB pipes on the remote machine ... "
        
        $allpipes = (get-childitem \\127.0.0.1\IPC$\pipe\ | sort {$_.FullName})
        for($k = 0; $k -lt $allpipes.length; $k++){
            Write-Host (" - \\PIPE\{0}" -f $allpipes[$k]);
        }
        Write-Host ("[+] Found {0} pipes." -f $allpipes.length)

    }
} else {
    # OneShot mode
    if ($Local) {
        # Listing Local SMB pipes in live mode
        Write-Host "[>] Listing open SMB pipes on the local machine ... "
        $allpipes = (get-childitem \\.\pipe\ | sort {$_.FullName})
        for($k = 0; $k -lt $allpipes.length; $k++){
            Write-Host (" - \\PIPE\{0}" -f $allpipes[$k]);
        }
        Write-Host ("[+] Found {0} pipes." -f $allpipes.length)
    } else {
        # Listing Remote SMB pipes in live mode
        Write-Host "[>] Listing open SMB pipes on the remote machine ... "
        New-SmbMapping -RemotePath ("\\{0}" -f $TargetIP) -Username ("{0}\{1}" -f $Domain, $Username) -Password $Password | Out-Null
        $allpipes = (get-childitem ("\\{0}\IPC$\" -f $TargetIP) | sort {$_.FullName})
        for($k = 0; $k -lt $allpipes.length; $k++){
            Write-Host (" - \\PIPE\{0}" -f $allpipes[$k]);
        }
        Write-Host ("[+] Found {0} pipes on {1}." -f $allpipes.length, $TargetIP)
        Remove-SmbMapping -RemotePath ("\\{0}" -f $TargetIP) -Force | Out-Null 
    }
}

