﻿#
# Copyright 2020-2021, Alexis La Goutte <alexis dot lagoutte at gmail dot com>
#
# SPDX-License-Identifier: Apache-2.0
#

#include common configuration
. ../common.ps1

BeforeAll {
    Connect-FGT @invokeParams
}

Describe "Get System Global" {

    It "Get System Global does not throw" {
        {
            Get-FGTSystemGlobal
        } | Should -Not -Throw
    }

    It "Get ALL Global with -skip" {
        $ss = Get-FGTSystemGlobal -skip
        @($ss).count | Should -Not -Be $NULL
    }

    Context "Search" {

        It "Search a System Setting by name (language)" {
            $ss = Get-FGTSystemGlobal -name "language"
            $ss.'language' | Should -Be -Not $NULL
            $ss.'timezone'  | Should -Be $NULL
        }

        It "Search 2 System Global by name (language, timezone)" {
            $ss = Get-FGTSystemGlobal -name "language", "timezone"
            $ss.'language' | Should -Be -Not $NULL
            $ss.'gui-dns-database'  | Should -Be $NULL
            $ss.'timezone'  | Should -Be -Not $NULL
        }

        It "Search 1 System Global by name (language)" {
            $ss = Get-FGTSystemGlobal -name "language"
            $ss.'language' | Should -Be -Not $NULL
            $ss.'timezone'  | Should -Be $NULL
        }
    }
}

Describe "Set System Global" {

    It "Change admintimeout to 480" {
        Set-FGTSystemGlobal -admintimeout 480
        $sg = Get-FGTSystemGlobal
        $sg.'admintimeout' | Should -Be "480"
    }

    It "Change admin_port (HTTP)" -Skip:($httpOnly) {
        Set-FGTSystemGlobal -admin_port 8080
        $sg = Get-FGTSystemGlobal
        $sg.'admin-port' | Should -Be "8080"
    }

    It "Change admin_sport (HTTPS)" -Skip:($httpOnly -eq $false) {
        Set-FGTSystemGlobal -admin_sport 8443
        $sg = Get-FGTSystemGlobal
        $sg.'admin-sport' | Should -Be "8443"
    }

    It "Change admin_ssh_port" {
        Set-FGTSystemGlobal -admin_ssh_port 8022
        $sg = Get-FGTSystemGlobal
        $sg.'admin-ssh-port' | Should -Be "8022"
    }

    It "Change alias" {
        Set-FGTSystemGlobal -alias "alias_PowerFGT"
        $sg = Get-FGTSystemGlobal
        $sg.'alias' | Should -Be "alias_PowerFGT"
    }

    It "Change dst to disable" {
        Set-FGTSystemGlobal -dst:$false
        $sg = Get-FGTSystemGlobal
        $sg.'dst' | Should -Be "disable"
    }

    It "Change dst to enable" {
        Set-FGTSystemGlobal -dst
        $sg = Get-FGTSystemGlobal
        $sg.'dst' | Should -Be "enable"
    }

    It "Change fortiextender to enable" {
        Set-FGTSystemGlobal -fortiextender
        $sg = Get-FGTSystemGlobal
        $sg.'fortiextender' | Should -Be "enable"
    }

    It "Change fortiextender to disable" {
        Set-FGTSystemGlobal -fortiextender:$false
        $sg = Get-FGTSystemGlobal
        $sg.'fortiextender' | Should -Be "disable"
    }

    It "Change hostname" {
        Set-FGTSystemGlobal -hostname "hostname_PowerFGT"
        $sg = Get-FGTSystemGlobal
        $sg.'hostname' | Should -Be "hostname_PowerFGT"
    }

    It "Change gui-certificates to disable" {
        Set-FGTSystemGlobal -gui_certificates:$false
        $sg = Get-FGTSystemGlobal
        $sg.'gui-certificates' | Should -Be "disable"
    }

    It "Change gui-certificates to enable" {
        Set-FGTSystemGlobal -gui_certificates
        $sg = Get-FGTSystemGlobal
        $sg.'gui-certificates' | Should -Be "enable"
    }

    It "Change gui-wireless-opensecurity to disable" {
        Set-FGTSystemGlobal -gui_wireless_opensecurity:$false
        $sg = Get-FGTSystemGlobal
        $sg.'gui-wireless-opensecurity' | Should -Be "disable"
    }

    It "Change gui-wireless-opensecurity to enable" {
        Set-FGTSystemGlobal -gui_wireless_opensecurity
        $sg = Get-FGTSystemGlobal
        $sg.'gui-wireless-opensecurity' | Should -Be "enable"
    }

    It "Change lldp-reception to enable" {
        Set-FGTSystemGlobal -lldp_reception
        $sg = Get-FGTSystemGlobal
        $sg.'lldp-reception' | Should -Be "enable"
    }

    It "Change lldp-reception to disable" {
        Set-FGTSystemGlobal -lldp_reception:$false
        $sg = Get-FGTSystemGlobal
        $sg.'lldp-reception' | Should -Be "disable"
    }

    It "Change lldp-transmission to enable" {
        Set-FGTSystemGlobal -lldp_transmission
        $sg = Get-FGTSystemGlobal
        $sg.'lldp-transmission' | Should -Be "enable"
    }

    It "Change lldp-transmission to disable" {
        Set-FGTSystemGlobal -lldp_transmission:$false
        $sg = Get-FGTSystemGlobal
        $sg.'lldp-transmission' | Should -Be "disable"
    }

    <# Disable need some other change...
    It "Change switch-controller to enable" {
        Set-FGTSystemGlobal -switch_controller
        $sg = Get-FGTSystemGlobal
        $sg.'switch-controller' | Should -Be "enable"
    }

    It "Change switch-controller to disable" {
        Set-FGTSystemGlobal -switch_controller:$false
        $sg = Get-FGTSystemGlobal
        $sg.'switch-controller' | Should -Be "disable"
    }
    #>

    It "Change timezone" {
        Set-FGTSystemGlobal -timezone 28
        $sg = Get-FGTSystemGlobal
        $sg.'timezone' | Should -Be "28"
    }

    <# Disable need some other change...
    It "Change wireless-controller to disable" {
        Set-FGTSystemGlobal -wireless_controller:$false
        $sg = Get-FGTSystemGlobal
        $sg.'wireless-controller' | Should -Be "disable"
    }

    It "Change wireless-controller to enable" {
        Set-FGTSystemGlobal -wireless_controller
        $sg = Get-FGTSystemGlobal
        $sg.'wireless-controller' | Should -Be "enable"
    }
    #>
}

AfterAll {
    Disconnect-FGT -confirm:$false
}