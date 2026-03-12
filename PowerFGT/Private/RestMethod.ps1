#
# Copyright 2018, Alexis La Goutte <alexis dot lagoutte at gmail dot com>
#
# SPDX-License-Identifier: Apache-2.0
#

function Invoke-FGTRestMethod {

    <#
      .SYNOPSIS
      Invoke RestMethod with FGT connection (internal) variable

      .DESCRIPTION
      Invoke RestMethod with FGT connection variable (token, csrf..)

      .EXAMPLE
      Invoke-FGTRestMethod -method "get" -uri "api/v2/cmdb/firewall/address"

      Invoke-RestMethod with FGT connection for get api/v2/cmdb/firewall/address uri

      .EXAMPLE
      Invoke-FGTRestMethod "api/v2/cmdb/firewall/address"

      Invoke-RestMethod with FGT connection for get api/v2/cmdb/firewall/address uri with default parameter

      .EXAMPLE
      Invoke-FGTRestMethod "-method "get" -uri api/v2/cmdb/firewall/address" -vdom vdomX

      Invoke-RestMethod with FGT connection for get api/v2/cmdb/firewall/address uri on vdomX

      .EXAMPLE
      Invoke-FGTRestMethod --method "post" -uri "api/v2/cmdb/firewall/address" -body $body

      Invoke-RestMethod with FGT connection for post api/v2/cmdb/firewall/address uri with $body payload

      .EXAMPLE
      Invoke-FGTRestMethod -method "get" -uri "api/v2/cmdb/firewall/address" -connection $fw2

      Invoke-RestMethod with $fw2 connection for get api/v2/cmdb/firewall/address uri

      .EXAMPLE
      Invoke-FGTRestMethod -method "get" -uri "api/v2/cmdb/firewall/address" -filter=name==FGT

      Invoke-RestMethod with FGT connection for get api/v2/cmdb/firewall/address uri with only name equal FGT

      .EXAMPLE
      Invoke-FGTRestMethod -method "get" -uri "api/v2/cmdb/firewall/address" -filter_attribute name -filter_value FGT

      Invoke-RestMethod with FGT connection for get api/v2/cmdb/firewall/address uri with filter attribute equal name and filter value equal FGT

      .EXAMPLE
      Invoke-FGTRestMethod -method "get" -uri "api/v2/cmdb/firewall/address" -filter_attribute name -filter_type contains -filter_value FGT

      Invoke-RestMethod with FGT connection for get api/v2/cmdb/firewall/address uri with filter attribute equal name and filter value contains FGT

      .EXAMPLE
      Invoke-FGTRestMethod -method "post" -uri "api/v2/cmdb/firewall/address" -uri_escape "My /% Address" -body $body

      Invoke-RestMethod with FGT connection for post api/v2/cmdb/firewall/address uri with uri escape (replace / or % by HTML code)

      .EXAMPLE
      Invoke-FGTRestMethod -method "post" -uri "api/v2/cmdb/firewall/address" -extra "action=move"

      Invoke-RestMethod with FGT connection for post api/v2/cmdb/firewall/address uri with extra uri (add ?action=move on this example)

      .EXAMPLE
      Invoke-FGTRestMethod -method "get" -uri "api/v2/cmdb/firewall/address" -skip

      Invoke-RestMethod with FGT connection for get api/v2/cmdb/firewall/address?&skip=1 uri with skip some value

    .EXAMPLE
      Invoke-FGTRestMethod -method "get" -uri "api/v2/cmdb/firewall/address" -meta

      Invoke-RestMethod with FGT connection for get api/v2/cmdb/firewall/address?&with_meta=1 uri with meta(data) of object (q_ref...)
    #>

    [CmdletBinding(DefaultParameterSetName = "default")]
    Param(
        [Parameter(Mandatory = $true, position = 1)]
        [String]$uri,
        [Parameter(Mandatory = $false)]
        [ValidateSet("GET", "PUT", "POST", "DELETE")]
        [String]$method = "GET",
        [Parameter(Mandatory = $false)]
        [psobject]$body,
        [Parameter(Mandatory = $false)]
        [switch]$meta,
        [Parameter(Mandatory = $false)]
        [switch]$skip,
        [Parameter(Mandatory = $false)]
        [String[]]$vdom,
        [Parameter(Mandatory = $false)]
        [Parameter (ParameterSetName = "filter")]
        [String]$filter,
        [Parameter(Mandatory = $false)]
        [Parameter (ParameterSetName = "filter_build")]
        [string]$filter_attribute,
        [Parameter(Mandatory = $false)]
        [ValidateSet('equal', 'contains')]
        [Parameter (ParameterSetName = "filter_build")]
        [string]$filter_type,
        [Parameter (Mandatory = $false)]
        [Parameter (ParameterSetName = "filter_build")]
        [psobject]$filter_value,
        [Parameter (Mandatory = $false)]
        [string]$uri_escape,
        [Parameter (Mandatory = $false)]
        [string]$extra,
        [Parameter(Mandatory = $false)]
        [psobject]$connection
    )

    Begin {
    }

    Process {

        if ($null -eq $connection ) {
            if ($null -eq $DefaultFGTConnection) {
                Throw "Not Connected. Connect to the Fortigate with Connect-FGT"
            }
            $connection = $DefaultFGTConnection
        }

        $Server = $connection.Server
        $httpOnly = $connection.httpOnly
        $port = $connection.port
        $headers = $connection.headers
        $invokeParams = $connection.invokeParams
        $sessionvariable = $connection.session

        $url = $uri
        if ( $PsBoundParameters.ContainsKey('uri_escape') ) {
            $url += "/" + ((($uri_escape -replace ("%", "%25")) -replace ("/", "%2f")) -replace ("\?", "%3f"))
        }
        #Extra parameter...
        if ($url -NotMatch "\?") {
            $url += "?"
        }

        if ( $PsBoundParameters.ContainsKey('meta') ) {
            $url += "&with_meta=1"
        }
        if ( $PsBoundParameters.ContainsKey('skip') ) {
            $url += "&skip=1"
        }
        if ( $PsBoundParameters.ContainsKey('vdom') ) {
            $vdom = $vdom -Join ','
            $url += "&vdom=$vdom"
        }
        elseif ($connection.vdom) {
            $vdom = $connection.vdom -Join ','
            $url += "&vdom=$vdom"
        }

        #filter only when there is a filter_attribute and filter_value
        if ($filter_attribute) {
            #use EscapeDataString for escape special character (% ? ...)
            switch ( $filter_type ) {
                "equal" {
                    $escaped_values = $filter_value | ForEach-Object { "$filter_attribute==$([uri]::EscapeDataString($_))" }
                    $filter = $escaped_values -join ","

                }
                "contains" {
                    $escaped_values = $filter_value | ForEach-Object { "$filter_attribute=@$([uri]::EscapeDataString($_))" }
                    $filter = $escaped_values -join ","

                }
                #by default set to equal..
                default {
                    $escaped_values = $filter_value | ForEach-Object { "$filter_attribute==$([uri]::EscapeDataString($_))" }
                    $filter = $escaped_values -join ","
                }
            }
        }

        if ( $filter ) {
            $url += "&filter=$filter"
        }

        if ( $PsBoundParameters.ContainsKey('extra') ) {
            $url += $extra
        }

        if ($connection.fmg) {

            $sessionvariable = $connection.websession
            $fullurl = "https://${Server}:${port}/jsonrpc"

            $target = "adom/$($connection.fmg.adom)/device/$($connection.fmg.target)"

            $data = @{
                target   = @($target)
                action   = $method
                resource = "/" + $url
                payload  = $body
            }
            $params = @{
                url  = "sys/proxy/json"
                data = $data

            }

            $irm_body = @{
                id      = $connection.id++
                method  = "exec"
                session = $connection.session
                verbose = 1
                params  = @($params)
            }

            try {
                Write-Verbose $fullurl
                Write-Verbose -message ($irm_body | ConvertTo-Json -Depth 10)

                $response = Invoke-RestMethod $fullurl -Method "POST" -body ($irm_body | ConvertTo-Json -Depth 10 -Compress) -Headers $headers -WebSession $sessionvariable @invokeParams
            }

            catch {
                Show-FGTException $_
                throw "Unable to use FortiManager API"
            }

            #Check status code
            Write-Verbose $response.result.status.code
            if ($response.result.status.code -ne "0") {
                throw "Unable to use FortiManager API (" + $response.result.status.code + ") " + $response.result.status.message
            }
            #Write-host $response.result.data.response.results
            Write-verbose ($response.result.data.response | Convertto-json)
            $response.result.data.response
        }
        else {

            if ($httpOnly) {
                $fullurl = "http://${Server}:${port}/{$url}"
            }
            else {
                $fullurl = "https://${Server}:${port}/${url}"
            }

            #Display (Full)url when verbose (no longer available with PS 7.2.x...)
            Write-Verbose $fullurl
            try {
                if ($body) {

                    #don't use pipeline to convertto-json because remove array...
                    $jbody = ConvertTo-Json $body -Depth 10
                    Write-Verbose -message ($jbody)

                    $response = Invoke-RestMethod $fullurl -Method $method -body (ConvertTo-Json $body -Depth 10 -Compress) -Headers $headers -WebSession $sessionvariable @invokeParams
                }
                else {
                    $response = Invoke-RestMethod $fullurl -Method $method -Headers $headers -WebSession $sessionvariable @invokeParams
                }
            }

            catch {
                Show-FGTException $_
                throw "Unable to use FortiGate API"
            }

            #Fix encoding with PS 5...
            if (("Desktop" -eq $PSVersionTable.PsEdition) -or ($null -eq $PSVersionTable.PsEdition)) {
                $encoding = [System.Text.Encoding]::GetEncoding('ISO-8859-1')
                (([System.Text.Encoding]::UTF8).GetString($encoding.GetBytes(($response | ConvertTo-json -Depth 10 -Compress)))) | ConvertFrom-Json
            }
            else {
                $response
            }
        }
    }

}