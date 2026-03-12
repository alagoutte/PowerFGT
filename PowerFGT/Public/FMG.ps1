#
# Copyright 2018, Alexis La Goutte <alexis dot lagoutte at gmail dot com>
#
# SPDX-License-Identifier: Apache-2.0
#

function Connect-FGTviaFMG {

    <#
      .SYNOPSIS
      Connect to a FortiGate via FortiManager

      .DESCRIPTION
      Connect to a FortiGate via FortiManager

      .EXAMPLE
      Connect-FGTviaFMG -Server 192.0.2.1

      Connect to a FortiManager with IP 192.0.2.1

      .EXAMPLE
      Connect-FGTviaFMG -Server 192.0.2.1 -SkipCertificateCheck

      Connect to a FortiManager with IP 192.0.2.1 and disable Certificate (chain) check

      .EXAMPLE
      Connect-FGTviaFMG -Server 192.0.2.1 -port 4443

      Connect to a FortiManager using HTTPS (with port 4443) with IP 192.0.2.1 using (Get-)credential

      .EXAMPLE
      $cred = get-credential
      Connect-FGTviaFMG -Server 192.0.2.1 -credential $cred

      Connect to a FortiManager with IP 192.0.2.1 and passing (Get-)credential

      .EXAMPLE
      $mysecpassword = ConvertTo-SecureString mypassword -AsPlainText -Force
      Connect-FGTviaFMG -Server 192.0.2.1 -Username manager -Password $mysecpassword

      Connect to a FortiManager with IP 192.0.2.1 using Username and Password

      .EXAMPLE
      $fw1 = Connect-FGTviaFMG -Server 192.0.2.1
      Connect to a FortiManager with IP 192.0.2.1 and store connection info to $fw1 variable

      .EXAMPLE
      $fw2 = Connect-FGTviaFMG -Server 192.0.2.1 -DefaultConnection:$false

      Connect to a FortiManager with IP 192.0.2.1 and store connection info to $fw2 variable
      and don't store connection on global ($DefaultFMGConnection) variable

  #>

    Param(
        [Parameter(Mandatory = $true, position = 1)]
        [String]$Server,
        [Parameter(Mandatory = $false)]
        [String]$Username,
        [Parameter(Mandatory = $false)]
        [SecureString]$Password,
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck = $false,
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 65535)]
        [int]$port,
        [Parameter(Mandatory = $false)]
        [int]$Timeout = 0,
        [Parameter(Mandatory = $false)]
        [string]$adom = "root",
        [Parameter(Mandatory = $true)]
        [string]$target,
        [Parameter(Mandatory = $false)]
        [boolean]$DefaultConnection = $true
    )

    Begin {
    }

    Process {

        $connection = @{server = ""; session = ""; httpOnly = $false; port = ""; headers = ""; invokeParams = ""; vdom = ""; version = ""; serial = ""; fmg = @() }
        $fmg = @{ adom = ""; version = "" ; target = ""; id = 0 }

        #If there is a password (and a user), create a credential
        if ($Password) {
            $Credential = New-Object System.Management.Automation.PSCredential($Username, $Password)
        }
        #Not Credential (and no password)
        if ($null -eq $Credential) {
            $Credential = Get-Credential -Message 'Please enter administrative credential for your FortiManager'
        }

        $postParams = @{
            id      = $fmg.id++
            method  = "exec"
            verbose = 1
            session = $null
            params  = @(
                @{
                    data = @{
                        user   = $Credential.username;
                        passwd = $Credential.GetNetworkCredential().Password;
                    }
                    url  = 'sys/login/user'
                }
            )
        }
        $invokeParams = @{DisableKeepAlive = $false; UseBasicParsing = $true; SkipCertificateCheck = $SkipCertificateCheck; TimeoutSec = $Timeout }

        if ("Desktop" -eq $PSVersionTable.PsEdition) {
            #Remove -SkipCertificateCheck from Invoke Parameter (not supported <= PS 5)
            $invokeParams.remove("SkipCertificateCheck")
        }
        else {
            #Core Edition
            #Remove -UseBasicParsing (Enable by default with PowerShell 6/Core)
            $invokeParams.remove("UseBasicParsing")
        }

        if (!$port) {
            $port = 443
        }

        #for PowerShell (<=) 5 (Desktop), Enable TLS 1.1, 1.2 and Disable SSL chain trust (needed/recommanded by FortiManager)
        if ("Desktop" -eq $PSVersionTable.PsEdition) {
            #Enable TLS 1.1 and 1.2
            Set-FGTCipherSSL
            if ($SkipCertificateCheck) {
                #Disable SSL chain trust...
                Set-FGTuntrustedSSL
            }
        }

        $uri = "https://${Server}:${port}/jsonrpc"

        try {
            $irmResponse = Invoke-RestMethod $uri -Method POST -Body ($postParams | ConvertTo-Json -Depth 10) -SessionVariable SFMG @invokeParams
        }
        catch {
            Show-FGTException $_
            throw "Unable to connect to FortiManager"
        }

        #
        if ($irmResponse.result.status.code -ne "0") {
            throw "Unable to connect to FortiManager (" + $irmResponse.result.status.code + ") " + $irmResponse.result.status.message
        }

        $connection.server = $server
        $connection.session = $irmResponse.session
        $connection.websession = $SFMG
        $connection.headers = $headers
        $connection.port = $port
        $connection.invokeParams = $invokeParams
        $fmg.adom = $adom
        $fmg.target = $target
        $connection.fmg = $fmg
        #get FMG version
        #$status = Invoke-FMGRestMethod sys/status -connection $fmg
        #$fmg.version = [version]"$($status.major).$($status.minor).$($status.patch)"

        if ( $DefaultConnection ) {
            set-variable -name DefaultFGTConnection -value $connection -scope Global
        }

        $connection
    }

    End {
    }
}

