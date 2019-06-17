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
        -BRANCH_TAG <BRANCH>            [Required] Select Git branch or tag e.g. $BRANCH
        -REVISION <REV>                 [Required] Package revision that append to version e.g. x.x.x-rev
        -DESTINATION <DESTINATION_DIR>  [Required] Destination directory
        -JOBS <N_JOBS>                  [Optional] Number of parallel jobs when compiling.
        -CHECKSUM <CHECKSUM_DIR>        [Optional] Generate checksum file for the generated package.
        -SIGN                           [Optional] Sign packages
        -help                           Show this help.
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
        -BRANCH_TAG <BRANCH>            [Required] Select Git branch or tag e.g. v3.9.2
        -REVISION <REV>                 [Required] Package revision that append to version e.g. x.x.x-rev
        -DESTINATION <DESTINATION_DIR>  [Required] Destination directory
        -JOBS <N_JOBS>                  [Optional] Number of parallel jobs when compiling.
        -CHECKSUM <CHECKSUM_DIR>        [Optional] Generate checksum file for the generated package.
        -SIGN                           [Optional] Sign packages
        -help                           Show this help.
        "
        Exit
    }

    else{

        [string]$MSI_NAME="wazuh-agent-${BRANCH_TAG}-${REVISION}.msi"

        [string]$DESTINATION_DOCKER=[string]$DESTINATION -replace "C:\\","/c/"
        [string]$DESTINATION_DOCKER=[string]$DESTINATION_DOCKER -replace "\\", "/"

        docker build -t wazuhmsi .
        docker run -it -v ${DESTINATION_DOCKER}:/home/wazuh_msi/output wazuhmsi $BRANCH_TAG $REVISION

        Set-Location -Path "$DESTINATION\wazuh\src\win32"
         if(($SIGN.isPresent)) {
            signtool sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "*.exe"
            signtool sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /td SHA256 "InstallerScripts.vbs"
         }
        .\wix\candle.exe -nologo "wazuh-installer.wxs" -out "wazuh-installer.wixobj" -ext WixUtilExtension -ext WixUiExtension

        .\wix\light.exe "wazuh-installer.wixobj" -out "$DESTINATION\$MSI_NAME"  -ext WixUtilExtension -ext WixUiExtension
        Set-Location -Path $DESTINATION
        if(($SIGN.isPresent)) {
            signtool sign /a /tr http://rfc3161timestamp.globalsign.com/advanced /d "$MSI_NAME" /td SHA256 "$MSI_NAME"
        }
        if(!($CHECKSUM -eq "")) {
            Set-Content -Path "$CHECKSUM\$MSI_NAME.sha512" -Value (Get-FileHash -Path "$DESTINATION\$MSI_NAME" -Algorithm SHA512)
            $SHA512=Get-Content -Path "$CHECKSUM\$MSI_NAME.sha512"
            $SHA512=$SHA512 -replace "@{Algorithm=SHA256; Hash=","" -replace "; Path=", " "
            Set-Content -Path "$CHECKSUM\$MSI_NAME.sha512" -Value  $SHA512
        }
        Remove-Item .\wazuh\ -Recurse

    }
