#!/bin/bash

# Tool to change the passwords of Open Distro internal users
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


readonly install_functions_path="install_functions"
readonly config_path="config"
readonly tools_path="tools"
readonly base_path="$(dirname $(readlink -f "$0"))"
readonly resources_install_functions="${base_path}/${functions_path}"
readonly resources_config="${base_path}/${config_path}"
readonly resources_tools="${base_path}/${tools_path}"

function common_getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Build unattended installation files."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") [-v] -i | -c | -p"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -i,  --installer"
    echo -e "                Builds the unattended installer single file wazuh-install.sh"
    echo -e ""
    echo -e "        -c,  --cert-tool"
    echo -e "                Builds the certificate creation tool cert-tool.sh"
    echo -e ""
    echo -e "        -p,  --password-tool"
    echo -e "                Builds the password creation and modification tool password-tool.sh"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete installation output."
    exit 1

}

function builder_installer() {
    output_script_path="wazuh-install.sh"

    ## Create installer script
    eval "touch ${output_script_path}"

    ## Add installation variables
    echo "${resources_install_functions}/install_variables.sh" >> "${output_script_path}"

    ## Add configuration files as variables
    configuration_files_tmp=$(find ${resources_config} -type f)
    read -r -a configuration_files <<< ${configuration_files_tmp}
    for index in "${!configuration_files[@]}"; do 
        config_file_name[$index]="$(eval "echo ${configuration_files[$index]} | sed 's|"${resources_config}/"||;s|/|_|g;s|.yml||'")"
    done
    for index in "${!config_file_name[@]}"; do
        eval "printf -v \"config_file_${config_file_name[$index]}\" '%s' '$(cat "${configuration_files[$index]}")'"
    done
}

function builder_main() {
    while [ -n "${1}" ]
    do
        case "${1}" in
            "-i"|"--installer")
                buildInstaller=1
                shift 1
                ;;
            "-c"|"--cert-tool")
                buildCertTool=1
                shift 1
                ;;
            "-c"|"--password-tool")
                buildPasswordTool=1
                shift 1
                ;;
            "-h"|"--help")
                builder_getHelp
                ;;
            "-v"|"--verbose")
                builderDebugEnabled=1
                builder_debug="2>&1 | tee -a ${builder_logfile}"
                shift 1
                ;;
            *)
                echo "Unknow option: "${1}""
                builder_getHelp
        esac
    done

    if [ -n "buildInstaller" ]; then
        build_installer
    fi
}