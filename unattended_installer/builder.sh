#!/bin/bash

# Tool to create wazuh-install.sh, wazuh-cert-tool.sh
# and wazuh-passwords-tool.sh
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

readonly base_path_builder="$(dirname "$(readlink -f "$0")")"
readonly resources_installer="${base_path_builder}/install_functions"
readonly resources_config="${base_path_builder}/config"
readonly resources_certs="${base_path_builder}/cert_tool"
readonly resources_passwords="${base_path_builder}/passwords_tool"
readonly resources_common="${base_path_builder}/common_functions"
readonly resources_download="${base_path_builder}/downloader"
source_branch="5.0.0"

function getHelp() {

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
    echo -e "                Builds the certificate creation tool wazuh-cert-tool.sh"
    echo -e ""
    echo -e "        -d [pre-release|staging],  --development"
    echo -e "                Use development repositories. By default it uses the pre-release package repository. If staging is specified, it will use that repository."
    echo -e ""
    echo -e "        -p,  --password-tool"
    echo -e "                Builds the password creation and modification tool wazuh-password-tool.sh"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
    exit 1

}

function buildInstaller() {

    checkDistDetectURL

    output_script_path="${base_path_builder}/wazuh-install.sh"

    ## Create installer script
    echo -n > "${output_script_path}"

    ## License
    echo "#!/bin/bash

# Wazuh installer
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation." >> "${output_script_path}"
    echo >> "${output_script_path}"

    ## Installation variables
    if [ -n "${development}" ]; then
        echo 'readonly development=1' >> "${output_script_path}"
        echo 'readonly repogpg="https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH"' >> "${output_script_path}"
        echo 'readonly repobaseurl="https://packages-dev.wazuh.com/'${devrepo}'"' >> "${output_script_path}"
        echo 'readonly reporelease="unstable"' >> "${output_script_path}"
        echo 'readonly filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.4.tar.gz"' >> "${output_script_path}"
        echo 'readonly bucket="packages-dev.wazuh.com"' >> "${output_script_path}"
        echo 'readonly repository="'"${devrepo}"'"' >> "${output_script_path}"
        sed -i 's|v${wazuh_version}|${wazuh_version}|g' "${resources_installer}/installVariables.sh"
    else
        echo 'readonly repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"' >> "${output_script_path}"
        echo 'readonly repobaseurl="https://packages.wazuh.com/4.x"' >> "${output_script_path}"
        echo 'readonly reporelease="stable"' >> "${output_script_path}"
        echo 'readonly filebeat_wazuh_module="${repobaseurl}/filebeat/wazuh-filebeat-0.4.tar.gz"' >> "${output_script_path}"
        echo 'readonly bucket="packages.wazuh.com"' >> "${output_script_path}"
        echo 'readonly repository="4.x"' >> "${output_script_path}"
    fi
    echo >> "${output_script_path}"
    grep -Ev '^#|^\s*$' ${resources_common}/commonVariables.sh >> "${output_script_path}"
    grep -Ev '^#|^\s*$' ${resources_installer}/installVariables.sh >> "${output_script_path}"
    echo >> "${output_script_path}"

    ## Configuration files as variables
    configuration_files=($(find "${resources_config}" -type f))
    config_file_name=($(eval "echo "${configuration_files[@]}" | sed 's|${resources_config}||g;s|/|_|g;s|.yml||g'"))
    for index in "${!config_file_name[@]}"; do
        echo "config_file${config_file_name[$index]}=\"$(cat "${configuration_files[$index]}" | sed 's|\"|\\\"|g;s|\$|\\\$|g')\"" >> "${output_script_path}"
        echo >> "${output_script_path}"
    done

    ## Sigint trap
    echo "trap installCommon_cleanExit SIGINT" >> "${output_script_path}"

    ## JAVA_HOME
    echo "export JAVA_HOME=\"/usr/share/wazuh-indexer/jdk/\"" >> "${output_script_path}"

    ## Functions for all install function modules
    install_modules=($(find "${resources_installer}" -type f))
    install_modules_names=($(eval "echo \"${install_modules[*]}\" | sed 's,${resources_installer}/,,g'"))
    for i in "${!install_modules[@]}"; do
        if [ "${install_modules_names[$i]}" != "installVariables.sh" ]; then
            echo "# ------------ ${install_modules_names[$i]} ------------ " >> "${output_script_path}"
            sed -n '/^function [a-zA-Z_]\(\)/,/^}/p' ${install_modules[$i]} >> "${output_script_path}"
            echo >> "${output_script_path}"
        fi
    done

    ## dist-detect.sh
    echo "function dist_detect() {" >> "${output_script_path}"
    curl -s "https://raw.githubusercontent.com/wazuh/wazuh/${source_branch}/src/init/dist-detect.sh" | sed '/^#/d' >> "${output_script_path}"
    echo "}" >> "${output_script_path}"

    ## Common functions
    sed -n '/^function [a-zA-Z_]\(\)/,/^}/p' "${resources_common}/common.sh" >> "${output_script_path}"

    ## Certificate tool library functions
    sed -n '/^function [a-zA-Z_]\(\)/,/^}/p' "${resources_certs}/certFunctions.sh" >> "${output_script_path}"

    ## Passwords tool library functions
    sed -n '/^function [a-zA-Z_]\(\)/,/^}/p' "${resources_passwords}/passwordsFunctions.sh" >> "${output_script_path}"

    ## Main function and call to it
    echo >> "${output_script_path}"
    echo "main \"\$@\"" >> "${output_script_path}"

    checkFilebeatURL

}

function buildPasswordsTool() {
    output_script_path="${base_path_builder}/wazuh-passwords-tool.sh"

    ## Create installer script
    echo -n > "${output_script_path}"

    ## License
    echo "#!/bin/bash

# Wazuh installer
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation." >> "${output_script_path}"

    ## Common and Passwords tool variables
    grep -Ev '^#|^\s*$' ${resources_common}/commonVariables.sh >> "${output_script_path}"
    grep -Ev '^#|^\s*$' "${resources_passwords}/passwordsVariables.sh" >> "${output_script_path}"
    echo >> "${output_script_path}"

    ## Functions for all password function modules
    passwords_modules=($(find "${resources_passwords}" -type f))
    passwords_modules_names=($(eval "echo "${passwords_modules[@]}" | sed 's,${resources_passwords}/,,g'"))
    for i in "${!passwords_modules[@]}"; do
        if [ "${passwords_modules[$i]}" != "passwordsVariables.sh" ]; then
            echo "# ------------ ${passwords_modules_names[$i]} ------------ " >> "${output_script_path}"
            sed -n '/^function [a-zA-Z_]\(\)/,/^}/p' "${passwords_modules[$i]}" >> "${output_script_path}"
            echo >> "${output_script_path}"
        fi
    done

    ## Common functions
    sed -n '/^function [a-zA-Z_]\(\)/,/^}/p' "${resources_common}/common.sh" >> "${output_script_path}"

    ## Call to main function
    echo >> "${output_script_path}"
    echo "main \"\$@\"" >> "${output_script_path}"
}

function buildCertsTool() {
    output_script_path="${base_path_builder}/wazuh-certs-tool.sh"

    ## Create installer script
    echo -n > "${output_script_path}"

    ## License
    echo "#!/bin/bash

# Wazuh installer
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation." >> "${output_script_path}"

    ## Common and Certs tool variables
    grep -Ev '^#|^\s*$' ${resources_common}/commonVariables.sh >> "${output_script_path}"
    grep -Ev '^#|^\s*$' "${resources_certs}/certVariables.sh" >> "${output_script_path}"
    echo >> "${output_script_path}"

    ## Functions for all certs tool function modules
    certs_modules=($(find "${resources_certs}" -type f))
    certs_modules_names=($(eval "echo "${certs_modules[@]}" | sed 's,${resources_certs}/,,g'"))
    for i in "${!certs_modules[@]}"; do
        if [ "${certs_modules[$i]}" != "certVariables.sh" ]; then
            echo "# ------------ ${certs_modules_names[$i]} ------------ " >> "${output_script_path}"
            sed -n '/^function [a-zA-Z_]\(\)/,/^}/p' "${certs_modules[$i]}" >> "${output_script_path}"
            echo >> "${output_script_path}"
        fi
    done

    ## Common functions
    sed -n '/^function [a-zA-Z_]\(\)/,/^}/p' "${resources_common}/common.sh" >> "${output_script_path}"

    ## Call to main function
    echo >> "${output_script_path}"
    echo "main \"\$@\"" >> "${output_script_path}"

}

function builder_main() {

    umask 066

    while [ -n "${1}" ]
    do
        case "${1}" in
            "-i"|"--installer")
                installer=1
                shift 1
                ;;
            "-c"|"--cert-tool")
                certTool=1
                shift 1
                ;;
            "-d"|"--development")
                development=1
                if [ -n "${2}" ] && [ "${2}" = "staging" ]; then
                    devrepo="staging"
                    shift 2
                elif [ -n "${2}" ] && [ "${2}" = "pre-release" ]; then
                    devrepo="pre-release"
                    shift 2
                else
                    devrepo="pre-release"
                    shift 1
                fi
                ;;
            "-p"|"--password-tool")
                passwordsTool=1
                shift 1
                ;;
            "-h"|"--help")
                getHelp
                ;;
            *)
                echo "Unknow option: \"${1}\""
                getHelp
        esac
    done

    if [ -n "${installer}" ]; then
        buildInstaller
        chmod 500 ${output_script_path}
        if [ -n "${change_filebeat_url}" ]; then
            sed -i -E "s|(https.+)master(.+wazuh-template.json)|\1\\$\\{source_branch\\}\2|"  "${resources_installer}/installVariables.sh"
        fi
        if [ -n "${development}" ]; then
            sed -i 's|${wazuh_version}|v${wazuh_version}|g' "${resources_installer}/installVariables.sh"
        fi
    fi

    if [ -n "${passwordsTool}" ]; then
        buildPasswordsTool
        chmod 500 ${output_script_path}
    fi

    if [ -n "${certTool}" ]; then
        buildCertsTool
        chmod 644 ${output_script_path}
    fi
}

function checkDistDetectURL() {

    urls=("https://raw.githubusercontent.com/wazuh/wazuh/${source_branch}/src/init/dist-detect.sh"
          "https://raw.githubusercontent.com/wazuh/wazuh/v${source_branch}/src/init/dist-detect.sh"
          "https://raw.githubusercontent.com/wazuh/wazuh/master/src/init/dist-detect.sh")

    for url in "${urls[@]}"; do
        eval "curl -s -o /dev/null '${url}' --retry 5 --retry-delay 5 --max-time 300 --fail"
        e_code="${PIPESTATUS[0]}"

        if [ "${e_code}" -eq 0 ]; then
            source_branch=$(echo "${url}" | awk -F'/' '{print $(NF-3)}')
            break
        fi
    done

    if [ "${e_code}" -ne 0 ]; then
        echo -e "Error: Could not get the dist-detect file."
        exit 1
    fi

}

function checkFilebeatURL() {

    # Import variables
    eval "$(grep -E "filebeat_wazuh_template=" "${resources_installer}/installVariables.sh")"
    new_filebeat_url="https://raw.githubusercontent.com/wazuh/wazuh/master/extensions/elasticsearch/7.x/wazuh-template.json"

    # Get the response of the URL and check it
    response=$(curl -I --write-out '%{http_code}' --silent --output /dev/null $filebeat_wazuh_template)
    if [ "${response}" != "200" ]; then
       	response=$(curl -I --write-out '%{http_code}' --silent --output /dev/null $new_filebeat_url)

        # Display error if both URLs do not get the resource
        if [ "${response}" != "200" ]; then
            echo -e "Error: Could not get the Filebeat Wazuh template. "
        # If matches, replace the variable of installVariables to the new one
        else
            echo -e "Changing Filebeat URL..."
            sed -i -E "s|filebeat_wazuh_template=.*|filebeat_wazuh_template=\"${new_filebeat_url}\"|g" "${resources_installer}/installVariables.sh"
            change_filebeat_url=1
        fi
    fi
}

builder_main "$@"
