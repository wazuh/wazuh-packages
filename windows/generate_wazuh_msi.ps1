param (
    #Mandatory
    [string]$BRANCH_TAG = "",
    [string]$REVISION = "",
    [string]$DESTINATION = "",
    #Optionals
    [Int]$JOBS = 4,
    [string]$CHECKSUM="",
    [switch]$SIGN,
    [switch]$help
    )

    if(($help.isPresent)) {
        "
        Usage: generate_wazuh_msi.ps1 -BRANCH_TAG <BRANCH> -REVISION <REV> -JOBS <N_JOBS>
        Arguments description:
        -BRANCH_TAG <BRANCH>        [Required] Select Git branch or tag e.g. $BRANCH
        -REVISION <REV>             [Required] Package revision that append to version e.g. x.x.x-rev
        -JOBS <N_JOBS>              [Optional] Number of parallel jobs when compiling.
        CHECKSUM                    [Optional] Generate checksum file for the generated package.
        -help                       Show this help.
        "
        Exit
    }

    if($BRANCH_TAG -eq "" -or $REVISION -eq "" -or $DESTINATION -eq ""){
        if($BRANCH_TAG -eq "")  {"        BRANCH_TAG is needed"}
        if($REVISION -eq "")    {"        REVISION is needed"}
        if($DESTINATION -eq "") {"        DESTINATION is needed"}
        "
        Usage: generate_wazuh_msi.ps1 -BRANCH_TAG <BRANCH> -REVISION <REV> -JOBS <N_JOBS>
        Arguments description:
        -BRANCH_TAG <BRANCH>        [Required] Select Git branch or tag e.g. $BRANCH
        -REVISION <REV>             [Required] Package revision that append to version e.g. x.x.x-rev
        -JOBS <N_JOBS>              [Optional] Number of parallel jobs when compiling.
        -SIGN                       [Optional] Sign package
        -CHECKSUM                   [Optional] Generate checksum file for the generated package.
        -help                       Show this help.
        "
        Exit
    }

    else{
        [string]$MSI_NAME="wazuh-agent-${VERSION}-${REVISION}.msi"
        [string]$DESTINATION2=[string]$DESTINATION -replace "C:\\","/c/"

        [string]$DESTINATION=[string]$DESTINATION -replace "\", "/"

        docker build -t wazuhmsi .
        docker run -it -v ${DESTINATION2}:/home/wazuh_msi/output wazuhmsi $BRANCH_TAG $REVISION

        cd $DESTINATION\wazuh\wazuh\src\win32
         if(($SIGN.isPresent)) {
            signtool sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "*.exe"
            signtool sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "InstallerScripts.vbs"
         }
        .\wix\candle.exe -nologo "wazuh-installer.wxs" -out "wazuh-installer.wixobj" -ext WixUtilExtension -ext WixUiExtension

        .\wix\light.exe "wazuh-installer.wixobj" -out "$DESTINATION\$MSI_NAME"  -ext WixUtilExtension -ext WixUiExtension
         cd $DESTINATION
        if(($SIGN.isPresent)) {
            signtool sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /d "$MSI_NAME" /td SHA256 "$MSI_NAME"
        }
        if(!($CHECKSUM -eq "")) {
            Set-Content -Path "$CHECKSUM\$MSI_NAME.sha512" -Value (Get-FileHash -Path "$DESTINATION\$MSI_NAME" -Algorithm SHA512)
        }
        Remove-Item .\wazuh\ -Recurse
        
    }
