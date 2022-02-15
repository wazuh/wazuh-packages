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
readonly base_path="$(dirname "$(readlink -f "$0")")"
readonly resources_install_modules="${base_path}/${install_functions_path}"
readonly resources_config="${base_path}/${config_path}"
readonly resources_tools="${base_path}/${tools_path}"
readonly builder_logfile="/var/log/wazuh_unattended_builder.log"

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

function build_installer() {
    output_script_path="wazuh_install.sh"

    ## Create installer script
    eval "echo -n > ${output_script_path}"

    ## License
    echo "#!/bin/bash

# Wazuh installer
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation." >> "${output_script_path}"

    ## Installation variables
    cat "${resources_install_modules}/install_variables.sh" >> "${output_script_path}"
    echo >> "${output_script_path}"

    ## Configuration files as variables
    configuration_files=($(find "${resources_config}" -type f))
    config_file_name=($(eval "echo "${configuration_files[@]}" | sed 's|${resources_config}||g;s|/|_|g;s|.yml||g'"))
    for index in "${!config_file_name[@]}"; do
        echo "config_file${config_file_name[$index]}=\"$(cat "${configuration_files[$index]}" | sed 's|\"|\\\"|g;s|\$|\\\$|g')\"" >> "${output_script_path}"
        echo >> "${output_script_path}"
    done

    ## Sigint trap
    echo "trap common_cleanExit SIGINT" >> "${output_script_path}"

    ## JAVA_HOME
    echo "export JAVA_HOME=\"/usr/share/wazuh-indexer/jdk/\"" >> "${output_script_path}"

    ## Debug
    echo "readonly logfile=\"/var/log/wazuh-unattended-installation.log\"" >> "${output_script_path}"
    echo "debug=\">> \${logfile} 2>&1\"" >> "${output_script_path}"

    ## Functions for all install function modules
    install_modules=($(find "${resources_install_modules}" -type f))
    for file in "${install_modules[@]}"; do
        echo "# ------------ ${file} ------------ " >> "${output_script_path}"
        sed -n '/^function [a-zA-Z_]\(\)/,/^}/p' "$file" >> "${output_script_path}"
        echo >> "${output_script_path}"
    done

    ## Tool functions
    tool_modules=($(find "${resources_tools}" -type f))
    tool_modules_names=($(eval "echo "${tool_modules[@]}" | sed 's,${resources_tools}/wazuh-,,g;s,-tool.sh,,g'"))
    for index in "${!tool_modules[@]}"; do
        echo "# ------------ ${tool_modules_names[$index]} ------------ " >> "${output_script_path}"
        eval "sed -n '/^function ${tool_modules_names[$index]}_[a-zA-Z_]\(\)/,/^}/p' "${tool_modules[$index]}"" >> "${output_script_path}"
        echo >> "${output_script_path}"
    done

    ## Main function and call to it
    sed -n '/^function main\(\)/,/^}/p' "${resources_install_modules}/main.sh" >> "${output_script_path}"
    echo >> "${output_script_path}" 
    echo "main \"\$@\"" >> "${output_script_path}"

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
                echo "Unknow option: \"${1}\""
                builder_getHelp
        esac
    done

    if [ -n "${buildInstaller}" ]; then
        build_installer
    fi
}

builder_main "$@"