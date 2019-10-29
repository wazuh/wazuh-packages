# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

param (
    [string]$READY_TO_RELEASE = "",
    [string]$OPTIONAL_REVISION = "",
    [string]$SIGN = "",
    [switch]$help
    )


$MSI_NAME = ""
$VERSION = ""

if(($help.isPresent)) {
    "
    This tool can be used to generate the Windows Wazuh agent msi package.

    PARAMETERS TO BUILD WAZUH-AGENT MSI:
        1. READY_TO_RELEASE: yes or no.
        2. OPTIONAL_REVISION: 1 or different
        3. SIGN: yes or no.

    USAGE:

        * WAZUH:
          $ ./generate_wazuh_msi.ps1 -READY_TO_RELEASE {{ yes|no }} -OPTIONAL_REVISION {{ BRANCH_TAG }} -SIGN {{ yes|no }}

            Build a devel msi:    $ ./generate_wazuh_msi.ps1 -READY_TO_RELEASE no -SIGN no
            Build a prod msi:     $ ./generate_wazuh_msi.ps1 -READY_TO_RELEASE yes -OPTIONAL_REVISION 2 -SIGN yes
    "
    Exit
}

# Get Power Shell version.
$PSversion = $PSVersionTable.PSVersion.Major
if ($PSversion -eq $null) {
    $PSversion = 1 # $PSVersionTable is new with Powershell 2.0
}

## Checking arguments
if($READY_TO_RELEASE -eq ""){
    "-READY_TO_RELEASE is required. Try -help to display arguments list."
    Write-Host "Press any key to continue ..."
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Exit
}

function ComputeMsiName() {

    ## Checking arguments
    if($OPTIONAL_REVISION -eq ""){
        Write-Host "-OPTIONAL_REVISION empty. Using default value."
        if($READY_TO_RELEASE -eq "yes"){
            $OPTIONAL_REVISION="1"
        }
        else{
            $OPTIONAL_REVISION = Get-Content REVISION
        }
    }
    $VERSION = Get-Content VERSION
    $VERSION = $VERSION -replace '[v]',''

    $MSI_NAME="wazuh-agent-$VERSION-$OPTIONAL_REVISION.msi"
    return $MSI_NAME
}

function BuildWazuhMsi(){
    $MSI_NAME = ComputeMsiName
    Write-Host "MSI_NAME = $MSI_NAME"

    if($SIGN -eq "yes"){
        # Sign .exe files and the InstallerScripts.vbs
        Write-Host "Signing .exe files..."
        & 'signtool.exe' sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 ".\*.exe"
        Write-Host "Signing .vbs files..."
        & 'signtool.exe' sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 ".\InstallerScripts.vbs"
    }

    Write-Host "Building MSI installer..."

    & 'candle.exe' -nologo .\wazuh-installer.wxs -out "wazuh-installer.wixobj" -ext WixUtilExtension -ext WixUiExtension
    & 'light.exe' ".\wazuh-installer.wixobj" -out $MSI_NAME  -ext WixUtilExtension -ext WixUiExtension

    if($SIGN -eq "yes"){
        # Write-Host "Signing $MSI_NAME..."
        & 'signtool.exe' sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /d $MSI_NAME /td SHA256 $MSI_NAME
    }
}


############################
# MAIN
############################

BuildWazuhMsi