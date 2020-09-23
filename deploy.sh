#!/bin/sh

# Constant variables
LINUX_SYSTEM="Linux"
MACOS_SYSTEM="Darwin"
SOLARIS_SYSTEM="SunOS"
HPUX_SYSTEM="HP-UX"
AIX_SYSTEM="AIX"
SOLARIS_10="5.10"
SOLARIS_11="5.11"
I386="i386"
SPARC="sparc"
APT_PACKAGE_MANAGER="apt"
YUM_PACKAGE_MANAGER="yum"
DNF_PACKAGE_MANAGER="dnf"
ZYPPER_PACKAGE_MANAGER="zypper"
WAZUH_REPO_VERSION_URL="https://raw.githubusercontent.com/wazuh/wazuh/master/src/VERSION"
PACKAGES_BASE_URL="https://packages.wazuh.com"
RED_COLOR="\033[0;31m"
GREEN_COLOR="\033[0;32m"
RESET_COLOR="\033[0m"
OSSEC_INIT="/etc/ossec-init.conf"

# Auxiliary variables
package_revision="1"
package_manager=""
package_version=""
package_major=""
system_os=""
system_architecture=""
system_kernel_version=""
sources_list_path=""
package_extension=""
package_s3_path=""
package_name=""
is_centos5=0
wazuhctl_arguments=""
ossec_log=""
wazuhctl=""
wazuh_agent_already_installed=0
installed_agent_version=""
need_upgrade_agent=0

# Input variables
manager_address=""
communication_port=""
communication_protocol=""
registration_address=""
registration_port=""
token=""
keep_alive=""
reconnection_time=""
registration_ca=""
registration_certificate=""
registration_key=""
agent_name=""
agent_group=""


# ----------------------------------------------------------------------------------------------------------------------


help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    --address                               [Required] Wazuh manager address"
    echo "    --version                               [Optional] Wazuh agent version to deploy"
    echo "    --port                                  [Optional] Wazuh manager port"
    echo "    --protocol                              [Optional] Wazuh manager protocol"
    echo "    --registration-address                  [Optional] Wazuh registration address"
    echo "    --registration-port                     [Optional] Wazuh registration port"
    echo "    --token                                 [Optional] Wazuh registration password"
    echo "    --keep-alive                            [Optional] Wazuh agent keep alive time"
    echo "    --reconnection-time                     [Optional] Wazuh agent reconnection time"
    echo "    --registration-ca                       [Optional] Certification Authority (CA) path"
    echo "    --registration-certificate              [Optional] Registration certificate path"
    echo "    --registration-key                      [Optional] Registration key path"
    echo "    --name                                  [Optional] Wazuh agent name"
    echo "    --group                                 [Optional] Wazuh agent group"
    echo "    --help, -h                              Show this help."
    echo

    exit $1
}

# ----------------------------------------------------------------------------------------------------------------------


error() {
    printf "\n\n${RED_COLOR}ERROR:${RESET_COLOR} $1\n\n"
    exit 1
}

# ----------------------------------------------------------------------------------------------------------------------


# 1 --> $1 > $2,  -1 --> > $1 < $2,  0 --> $1=$2
compare_versions() {
    major_1=$(echo $1 | cut -d . -f 1)
    minor_1=$(echo $1 | cut -d . -f 2)
    patch_1=$(echo $1 | cut -d . -f 3)

    major_2=$(echo $2 | cut -d . -f 1)
    minor_2=$(echo $2 | cut -d . -f 2)
    patch_2=$(echo $2 | cut -d . -f 3)

    if [ ${major_1} -gt ${major_2} ]; then
        echo "1" && return 0
    elif [ ${major_2} -gt ${major_1} ]; then
        echo "-1" && return 0
    else
        if [ ${minor_1} -gt ${minor_2} ]; then
            echo "1" && return 0
        elif [ ${minor_2} -gt ${minor_1} ]; then
            echo "-1" && return 0
        else
            if [ ${patch_1} -gt ${patch_2} ]; then
                echo "1" && return 0
            elif [ ${patch_2} -gt ${patch_1} ]; then
                echo "-1" && return 0
            else
                echo "0" && return 0
            fi
        fi
    fi
}

# ----------------------------------------------------------------------------------------------------------------------

set_system_info() {
    system_os=$(uname -s 2>/dev/null || echo undefined)
    system_architecture=$(uname -p 2>/dev/null || echo undefined)
    system_kernel_version=$(uname -r 2>/dev/null || echo undefined)


    if [ "${system_os}" = "undefined" ] || [ "${system_architecture}" = "undefined" ] || \
       [ "${system_kernel_version}" = "undefined" ]; then
        error "Could not detect some system info. os=${system_os}, arch=${system_architecture}, "\
              "kernel_version=${system_kernel_version}"
    fi

    # Check if CentOS 5
    if [ "${system_os}" = "${LINUX_SYSTEM}" ]; then
        rpm_version=$(rpm -q centos-release 2> /dev/null)
        if [ -z "${rpm_version##*centos-release-5*}" ]; then
            is_centos5=1
        fi
    fi
}

# ----------------------------------------------------------------------------------------------------------------------


set_package_manager() {
    if [ "${system_os}" = "${LINUX_SYSTEM}" ]; then
        if [ -n "$(command -v zypper)" ]; then
            package_manager=${ZYPPER_PACKAGE_MANAGER}
            sources_list_path="/etc/zypp/repos.d/wazuh.repo"
        elif [ -n "$(command -v dnf)" ]; then
            package_manager=${DNF_PACKAGE_MANAGER}
            sources_list_path="/etc/yum.repos.d/wazuh.repo"
        elif [ -n "$(command -v yum)" ]; then
            package_manager=${YUM_PACKAGE_MANAGER}
            sources_list_path="/etc/yum.repos.d/wazuh.repo"
        elif [ -n "$(command -v apt-get)" ]; then
            package_manager=${APT_PACKAGE_MANAGER}
            sources_list_path="/etc/apt/sources.list.d/wazuh.list"
        fi
    fi
}

# ----------------------------------------------------------------------------------------------------------------------


set_package_version() {
    if [ -z "${package_version}" ]; then
        package_version=$(get_last_package_version)
    fi

    package_version=$(echo ${package_version} | sed 's/v//g')
    package_major=$(echo ${package_version} | cut -c 1)
}

# ----------------------------------------------------------------------------------------------------------------------


set_package_extension() {
    case "${system_os}" in
        ${LINUX_SYSTEM})
            case "${package_manager}" in
                ${APT_PACKAGE_MANAGER})
                    package_extension="deb"
                ;;

                ${YUM_PACKAGE_MANAGER})
                    package_extension="rpm"
                ;;

                *)
                    error "Could not detect the Linux package extension"
            esac
        ;;

        ${MACOS_SYSTEM})
            package_extension="pkg"
        ;;

        ${SOLARIS_SYSTEM})
            case "${system_kernel_version}" in
                ${SOLARIS_10})
                    package_extension="pkg"
                ;;

                ${SOLARIS_11})
                    package_extension="p5p"
                ;;

                *)
                    error "Could not detect the Solaris package extension"
            esac
        ;;

        ${AIX_SYSTEM})
            package_extension="rpm"
        ;;

        ${HPUX_SYSTEM})
            package_extension="tar"
        ;;

        *)
            error "Could not detect the package extension"
    esac
}

# ----------------------------------------------------------------------------------------------------------------------


set_package_s3_path() {
    case "${system_os}" in
        ${MACOS_SYSTEM})
            package_s3_path="osx"
        ;;

        ${SOLARIS_SYSTEM})
            case "${system_kernel_version}" in
                ${SOLARIS_10})
                    solaris_version="10"
                ;;

                ${SOLARIS_11})
                    solaris_version="11"
                ;;

                *)
                    error "Could not detect Solaris version"
            esac

            if [ "${system_architecture}" != "${I386}" ] && [ "${system_architecture}" != "${SPARC}" ]; then
                error "Bad Solaris architecture detected"
            fi

            package_s3_path="solaris/${system_architecture}/${solaris_version}"
        ;;

        ${AIX_SYSTEM})
            package_s3_path="aix"
        ;;

        ${HPUX_SYSTEM})
            package_s3_path="hp-ux"
        ;;
    esac
}

# ----------------------------------------------------------------------------------------------------------------------


set_package_revision() {
    revision=1
    check_new_revision=1
    custom_package_name=$package_name

    # Get last package revision
    while [ $check_new_revision = 1 ]; do
        custom_package_name=$(echo ${custom_package_name} | sed "s/-${revision}/-$((revision+1))/g")
        custom_package_url="${PACKAGES_BASE_URL}/${package_major}.x/${package_s3_path}/${custom_package_name}"

        exist=$(curl --head --silent --fail $custom_package_url 2> /dev/null)
        if [ -z "${exist}" ]; then
            check_new_revision=0
        else
            revision=$((revision+1))
        fi
    done

    package_revision=$revision
}

# ----------------------------------------------------------------------------------------------------------------------


set_package_name() {
    set_package_extension

    case "${system_os}" in
        ${MACOS_SYSTEM})
            package_name="wazuh-agent-${package_version}-${package_revision}.${package_extension}"
        ;;

        ${SOLARIS_SYSTEM})
            case "${system_kernel_version}" in
                ${SOLARIS_10})
                    solaris_alias="sol10"
                ;;

                ${SOLARIS_11})
                    solaris_alias="sol11"
                ;;

                *)
                    error "Could not set solaris package name"
            esac

            package_name="wazuh-agent_v${package_version}-${solaris_alias}-${system_architecture}.${package_extension}"
        ;;

        ${AIX_SYSTEM})
            package_name="wazuh-agent-${package_version}-${package_revision}_.aix.ppc.${package_extension}"
        ;;

        ${HPUX_SYSTEM})
            package_name="wazuh-agent-${package_version}-hpux-11v3-ia64.${package_extension}"
        ;;
    esac
}

# ----------------------------------------------------------------------------------------------------------------------


set_paths() {
    if [ "${system_os}" = "${MACOS_SYSTEM}" ]; then
        ossec_log="/Library/Ossec/logs/ossec.log"
        wazuhctl="/Library/Ossec/bin/wazuhctl"
    else
        ossec_log="/var/ossec/logs/ossec.log"
        wazuhctl="/var/ossec/bin/wazuhctl"
    fi
}

# ----------------------------------------------------------------------------------------------------------------------


set_installed_agent_vars() {
    if [ -f "${OSSEC_INIT}" ]; then
        wazuh_agent_already_installed=1
        installed_agent_version=$(grep VERSION /etc/ossec-init.conf | sed 's/VERSION="v//g' | sed 's/"//g')

        compare_result=$(compare_versions "${package_version}" "${installed_agent_version}")

        if [ $compare_result = 1 ]; then
            need_upgrade_agent=1
        fi
    fi
}

# ----------------------------------------------------------------------------------------------------------------------


get_last_package_version() {
    curl ${WAZUH_REPO_VERSION_URL} 2> /dev/null
}

# ----------------------------------------------------------------------------------------------------------------------


check_dependencies() {
    if [ "${package_manager}" = "${APT_PACKAGE_MANAGER}" ];then
        ${APT_PACKAGE_MANAGER} install apt-transport-https lsb-release gnupg2 -y
    fi
}

# ----------------------------------------------------------------------------------------------------------------------


initialize_vars() {
    set_system_info
    set_package_manager
    set_package_version
    set_paths
    set_installed_agent_vars
}

# ----------------------------------------------------------------------------------------------------------------------


check_package_exist() {
    exist=$(curl --head --silent --fail $1 2> /dev/null)

    if [ -z "${exist}" ]; then
        error "The custom package version ${package_version} is not available, maybe you wrote it wrong. e.g 4.0.0"
    fi
}

# ----------------------------------------------------------------------------------------------------------------------

download_package() {
    set_package_s3_path
    set_package_name

    package_url="${PACKAGES_BASE_URL}/${package_major}.x/${package_s3_path}/${package_name}"

    #check_package_exist $package_url

    # Solaris does not have custom revisions, so it is not set
    if [ "${system_os}" != "${SOLARIS_SYSTEM}" ]; then
        set_package_revision
    fi

    echo "Downloading package ${package_name}..."

    # DELETE THIS WHEN PRODUCTION

    if [ ${package_major} -eq 4 ] && [ "${system_os}" = "${MACOS_SYSTEM}" ]; then
        echo "Installing custom package..."
        package_name="wazuh-agent-4.0.0-jmv74211.pkg"
        package_url="https://packages-dev.wazuh.com/warehouse/test/4.0/macos/wazuh-agent-4.0.0-jmv74211.pkg"
    fi

    if [ ${package_major} -eq 4 ] && [ "${system_os}" = "${SOLARIS_SYSTEM}" ] && [ "${system_kernel_version}" = ${SOLARIS_10} ]; then
        echo "Installing custom package..."
        package_name="wazuh-agent_v4.0.0-jmv74211-sol10-i386.pkg"
        package_url="https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/warehouse/test/4.0/solaris/i386/10/wazuh-agent_v4.0.0-jmv74211-sol10-i386.pkg"

    elif [ ${package_major} -eq 4 ] && [ "${system_os}" = "${SOLARIS_SYSTEM}" ] && [ "${system_kernel_version}" = ${SOLARIS_11} ]; then
        echo "Installing custom package..."
        package_name="wazuh-agent_v4.0.0-jmv74211-sol11-i386.p5p"
        package_url="https://s3-us-west-1.amazonaws.com/packages-dev.wazuh.com/warehouse/test/4.0/solaris/i386/11/wazuh-agent_v4.0.0-jmv74211-sol11-i386.p5p"
    fi

    curl -OL ${package_url} 2> /dev/null

    file_downloaded=$(ls | grep "${package_name}" | wc -l)

    if [ ${file_downloaded} -eq 0 ];then
        error "Could not download the Wazuh package"
    fi
}

# ----------------------------------------------------------------------------------------------------------------------


clean_files() {
    rm -f ${package_name}

    if [ "${system_os}" = "${SOLARIS_SYSTEM}" ] && [ "${system_kernel_version}" = "${SOLARIS_10}" ]; then
        rm -rf noaskfile
    fi
}

# ----------------------------------------------------------------------------------------------------------------------

add_repository() {
    echo "Adding repository..."
    case "${package_manager}" in
        ${APT_PACKAGE_MANAGER})
            curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
            echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee ${sources_list_path}
            $APT_PACKAGE_MANAGER update
        ;;

        ${YUM_PACKAGE_MANAGER} | ${DNF_PACKAGE_MANAGER} | ${ZYPPER_PACKAGE_MANAGER})
            if [ $is_centos5 = 1 ]; then
                rpm --import http://packages.wazuh.com/key/GPG-KEY-WAZUH-5
                echo -e ""\
                    "[wazuh_repo]\n"\
                    "gpgcheck=1\n"\
                    "gpgkey=http://packages.wazuh.com/key/GPG-KEY-WAZUH-5\n"\
                    "enabled=1\n"\
                    "name=Wazuh repository\n"\
                    "baseurl=http://packages.wazuh.com/3.x/yum/5/\$basearch/\n"\
                    "protect=1\n" | sed 's/^\s//g' > ${sources_list_path}
            else
                rpm --import http://packages.wazuh.com/key/GPG-KEY-WAZUH
                echo -e ""\
                    "[wazuh_repo]\n"\
                    "gpgcheck=1\n"\
                    "gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\n"\
                    "enabled=1\n"\
                    "name=Wazuh repository\n"\
                    "baseurl=https://packages.wazuh.com/3.x/yum/\n"\
                    "protect=1\n" | sed 's/^\s//g' > ${sources_list_path}
            fi
            ;;

        *)
            error "No repository detected"
  esac
}

# ----------------------------------------------------------------------------------------------------------------------


install_agent() {
    case "${system_os}" in
        ${LINUX_SYSTEM})
            add_repository
            package_revision="*"
            case "${package_manager}" in
                ${APT_PACKAGE_MANAGER})
                    echo "Installing wazuh-agent-${package_version}-${package_revision} using ${package_manager}"\
                         "repository..."
                    ${package_manager} install wazuh-agent=${package_version}-${package_revision} -y
                ;;

                ${YUM_PACKAGE_MANAGER} | ${DNF_PACKAGE_MANAGER}| ${ZYPPER_PACKAGE_MANAGER})
                echo "Installing wazuh-agent-${package_version}-${package_revision} using ${package_manager}"\
                         "repository..."
                    ${package_manager} install wazuh-agent-${package_version}-${package_revision} -y
                ;;

                ${ZYPPER_PACKAGE_MANAGER})
                    # Zypper will install latest package revision by default
                    echo "Installing wazuh-agent v${package_version}-${package_revision} using ${package_manager}"\
                         "repository..."
                    ${package_manager} install -y wazuh-agent-${package_version}
                ;;

                *)
                    error "Could not install agent due to it has not matched with package manager"
            esac
        ;;

        ${MACOS_SYSTEM})
            download_package
            echo "Installing macOS wazuh-agent v${package_version}-${package_revision} ..."
            installer -pkg ${package_name} -target /
        ;;

        ${SOLARIS_SYSTEM})
            download_package

            case "${system_kernel_version}" in
                ${SOLARIS_10})
                    # Create noask file to run unattended installation
                    echo "action=nocheck" > noaskfile
                    echo "Installing Solaris 10 wazuh-agent v${package_version}-${package_revision} ..."
                    pkgadd -a noaskfile -d ${package_name} -n all
                ;;

                ${SOLARIS_11})
                    echo "Installing Solaris 11 wazuh-agent v${package_version}-${package_revision} ..."
                    pkg install -g ${package_name} wazuh-agent 1>/dev/null
                ;;

                *)
                    error "Could not install Solaris package"
            esac
        ;;

        ${AIX_SYSTEM})
            echo "Installing AIX wazuh-agent v${package_version}-${package_revision} ..."
            rpm -ivh ${package_name} 1>/dev/null
        ;;

        ${HPUX_SYSTEM})
            groupadd ossec
            useradd -G ossec ossec
            echo "Installing HP-UX wazuh-agent v${package_version}-${package_revision} ..."
            tar -xvf ${package_name} 1>/dev/null
        ;;

        *)
            error "System not supported for agent installation"
    esac
}

# ----------------------------------------------------------------------------------------------------------------------


upgrade_agent() {
    case "${system_os}" in
        ${LINUX_SYSTEM} | ${MACOS_SYSTEM})
            echo "Upgrading agent from ${installed_agent_versionv} to v${package_version}"
            install_agent
        ;;

        ${AIX_SYSTEM})
            download_package
            echo "Upgrading agent from ${installed_agent_versionv} to v${package_version}"
            rpm -U ${package_name} -y 1>/dev/null
        ;;

        ${HP-UX})
            download_package
            echo "Upgrading agent from ${installed_agent_versionv} to v${package_version}"
            rpm -U ${package_name} -y 1>/dev/null
        ;;


        *)
            error "The agent could not be updated. Detected system is not allowed"
}

# ----------------------------------------------------------------------------------------------------------------------

print_vars() {
    echo "address = ${manager_address}"
    echo "version = ${package_version}"
    echo "port = ${communication_port}"
    echo "protocol = ${communication_protocol}"
    echo "registration-address = ${registration_address}"
    echo "registration-port = ${registration_port}"
    echo "token = ${token}"
    echo "keep-alive = ${keep_alive}"
    echo "reconnection-time = ${reconnection_time}"
    echo "registration-ca = ${registration_ca}"
    echo "registration-certificate = ${registration_certificate}"
    echo "registration-key = ${registration_key}"
    echo "name = ${agent_name}"
    echo "group = ${agent_group}"
}

# ----------------------------------------------------------------------------------------------------------------------


installation_wizard (){
    current_version=$(get_last_package_version)

    echo
    echo "------------------------------ WAZUH AGENT INSTALLATION WIZARD ------------------------------"
    printf "Wazuh manager IP address [Required]: " && read -r manager_address
    printf "Wazuh agent version [${current_version}]: " && read -r package_version
    printf "Wazuh agent name [$(echo $HOSTNAME)]: " && read -r agent_name
    printf "Wazuh agent group [default]: " && read -r agent_group

    printf "Wazuh manager communication port [1514]: " && read -r communication_port
    printf "Wazuh manager communication protocol [udp]: " && read -r communication_protocol
    printf "Wazuh manager registration port [1515]: " && read -r registration_port
    printf "Wazuh manager registration token []: " && read -r token
    printf "Wazuh agent keep-alive []: " && read -r keep_alive
    printf "Wazuh agent reconnection-time [60]: " && read -r reconnection_time

    printf "Wazuh registration-ca []: " && read -r registration_ca
    printf "Wazuh registration certificate []: " && read -r registration_certificate
    printf "Wazuh registration key[]: " && read -r registration_key
    printf "Wazuh manager registration address (Only for cluster environments) []: " && read -r protocol

    echo "-------------------------------------------------------------------------------------------"
    echo

    if [ ! -z "${manager_address}" ]; then wazuhctl_arguments="${wazuhctl_arguments} --address ${manager_address}"; fi
    if [ ! -z "${agent_name}" ]; then wazuhctl_arguments="${wazuhctl_arguments} --name ${agent_name}"; fi
    if [ ! -z "${agent_group}" ]; then wazuhctl_arguments="${wazuhctl_arguments} --group ${agent_group}"; fi
    if [ ! -z "${token}" ]; then wazuhctl_arguments="${wazuhctl_arguments} --token ${token}"; fi
    if [ ! -z "${communication_port}" ]; then wazuhctl_arguments="${wazuhctl_arguments}\
        --port ${communication_port}"; fi
    if [ ! -z "${communication_protocol}" ]; then wazuhctl_arguments="${wazuhctl_arguments}\
        --protocol ${communication_protocol}"; fi
    if [ ! -z "${registration_address}" ]; then wazuhctl_arguments="${wazuhctl_arguments}\
        --registration-address ${registration_address}"; fi
    if [ ! -z "${registration_port}" ]; then wazuhctl_arguments="${wazuhctl_arguments}\
        --registration-port ${registration_port1}"; fi
    if [ ! -z "${keep_alive}" ]; then wazuhctl_arguments="${wazuhctl_arguments}\
        --keep-alive ${keep_alive}"; fi
    if [ ! -z "${reconnection_time}" ]; then wazuhctl_arguments="${wazuhctl_arguments}\
        --reconnection-time ${reconnection_time}"; fi
    if [ ! -z "${registration_ca}" ]; then wazuhctl_arguments="${wazuhctl_arguments}\
        --registration-ca  ${registration_ca}"; fi
    if [ ! -z "${registration_certificate}" ]; then wazuhctl_arguments="${wazuhctl_arguments}\
        --registration-certificate ${registration_certificate}"; fi
    if [ ! -z "${registration_key}" ]; then wazuhctl_arguments="${wazuhctl_arguments}\
        --registration-key ${registration_key}"; fi
}

# ----------------------------------------------------------------------------------------------------------------------

start_agent() {
    echo "Starting agent..."

    case "${system_os}" in
        ${LINUX_SYSTEM})
            systemctl start wazuh-agent 1>/dev/null
        ;;

        ${MACOS_SYSTEM})
           /Library/Ossec/bin/ossec-control restart 1>/dev/null
        ;;

        *)
            /var/ossec/bin/ossec-control start 1>/dev/null
    esac
}


# ----------------------------------------------------------------------------------------------------------------------

configure_agent() {
    if [ "${package_major}" -lt 4 ]; then
        echo "Versions prior to 4.0.0 cannot be autoconfigured, skipping..."
        return
    fi

    echo "Configuring agent..."

    ${wazuhctl} enroll ${wazuhctl_arguments}
}

# ----------------------------------------------------------------------------------------------------------------------


check_agent_registration_status() {
    printf "Checking the registration status ... "

    log_message="Valid key received"

    log_ocurrences=$(grep -i "${log_message}" $ossec_log | wc -l)

    if [ $log_ocurrences -lt 1 ]; then
        error "The agent could not register correctly, please check the configuration entered"
    fi

    printf "${GREEN_COLOR}OK${RESET_COLOR}\n"
}

# ----------------------------------------------------------------------------------------------------------------------


check_agent_connection() {
    printf "Checking the agent connection with the manager ... "

    log_message="Connected to the server"

    log_ocurrences=$(grep -i "${log_message}" $ossec_log | wc -l)

    if [ $log_ocurrences -lt 2 ]; then
        error "The agent could not connect to the server, please check the configuration entered"
    fi

    printf "${GREEN_COLOR}OK${RESET_COLOR}\n"
}

# ----------------------------------------------------------------------------------------------------------------------


check_log_errors() {
    printf "Checking for errors in the ossec.log ... "

    errors_found=$(egrep -i "ERROR|CRITICAL" $ossec_log | wc -l)

    if [ $errors_found -gt 0 ]; then
        error "Errors have been found in the ossec.log, please check the configuration entered"
    fi

    printf "${GREEN_COLOR}OK${RESET_COLOR}\n"
}

# ----------------------------------------------------------------------------------------------------------------------


health_check() {
    echo "Doing a health check of the agent ..."
    sleep 30
    check_agent_registration_status
    check_agent_connection
    check_log_errors
}

# ----------------------------------------------------------------------------------------------------------------------


main() {
    if [ $# -eq 0 ]; then
        installation_wizard
    else
        while [ -n "$1" ]
        do
            case "$1" in
                "--address")
                    if [ -n "$2" ]; then
                        manager_address=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --address $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--version")
                    if [ -n "$2" ]; then
                        package_version=$2
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--port")
                    if [ -n "$2" ]; then
                        communication_port=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --port $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--protocol")
                    if [ -n "$2" ]; then
                        communication_protocol=$2
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--registration-address")
                    if [ -n "$2" ]; then
                        registration_address=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --registration-address $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;


                "--registration-port")
                    if [ -n "$2" ]; then
                        registration_port=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --registration-port $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--token")
                    if [ -n "$2" ]; then
                        token=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --token $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--keep-alive")
                    if [ -n "$2" ]; then
                        keep_alive=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --keep-alive $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--reconnection-time")
                    if [ -n "$2" ]; then
                        reconnection_time=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --reconnection-time $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--registration-ca")
                    if [ -n "$2" ]; then
                        registration_ca=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --registration-ca $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;


                "--registration-certificate")
                    if [ -n "$2" ]; then
                        registration_certificate=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --registration-certificate $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--registration-key")
                    if [ -n "$2" ]; then
                        registration_key=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --registration-key $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--name")
                    if [ -n "$2" ]; then
                        agent_name=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --name $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "--group")
                    if [ -n "$2" ]; then
                        agent_group=$2
                        wazuhctl_arguments="${wazuhctl_arguments} --group $2"
                        shift 2
                    else
                        help 1
                    fi
                ;;

                "-h"|"--help")
                    help 0
                ;;

                *)
                    help 1
            esac
        done
    fi

    if [ -z "${manager_address}" ]; then
        error "--address is a required parameter"
    fi

    initialize_vars

    if [ $wazuh_agent_already_installed = 0 ]; then
        check_dependencies
        install_agent
        clean_files
    elif [ $wazuh_agent_already_installed = 1 ] && [ $need_upgrade_agent = 1 ]; then
        upgrade_agent
    else
        echo "It has been detected that the Wazuh agent is already installed, skipping installation..."
    fi


    if [ "${package_major}" -lt 4 ]; then
        echo "Versions prior to 4.0.0 cannot be autoconfigured, skipping..."
    else
        configure_agent
        start_agent
        health_check
    fi

    printf "${GREEN_COLOR}Process completed!${RESET_COLOR}\n"
}

# ----------------------------------------------------------------------------------------------------------------------


main "$@"
