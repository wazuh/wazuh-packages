param (
    #Mandatory
    [string]$BRANCH_TAG = "",
    [string]$REVISION = "",
    [string]$DESTINATION = "",
    [switch]$CHECKSUM,
    #Optionals
    [Int]$JOBS = 4,
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
        -h, --help                  Show this help.
        "
        Exit
    }

    docker build -t wazuhmsi .
    docker run -t --rm wazuhmsi $BRANCH_TAG $REVISION
