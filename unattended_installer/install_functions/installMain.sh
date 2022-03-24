# Wazuh installer - main functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "$0") - Install and configure Wazuh central components: Wazuh manager, Wazuh indexer and Wazuh dashboard."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "$0") [OPTIONS] -a | -c | -s | -wi <indexer-node-name> | -wd <dashboards-node-name> | -ws <wazuh-node-name>"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --all-in-one"
    echo -e "                Install and configure Wazuh server, Wazuh indexer, Wazuh dashboard and Filebeat."
    echo -e ""
    echo -e "        -c,  --configfile <path-to-config-yml>"
    echo -e "                Path to the configuration file. By default: ${base_path}/config.yml"
    echo -e ""
    echo -e "        -ds,  --disable-spinner"
    echo -e "                Disables the spinner indicator."
    echo -e ""
    echo -e "        -F,  --force-dashboard"
    echo -e "                Ignore Wazuh indexer cluster connection errors in Wazuh dashboard installation"
    echo -e ""
    echo -e "        -g,  --generate-configurations"
    echo -e "                Generate ${tar_file} file from ${config_file} containing the files that will be needed for installation. You will need to copy this file to other hosts in distributed deployments."
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Display this help and exit."
    echo -e ""
    echo -e "        -i,  --ignore-check"
    echo -e "                Ignore check for system compatibility and minimum hardware requirements."
    echo -e ""
    echo -e "        -o,  --overwrite"
    echo -e "                Overwrites previously installed components. This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -s,  --start-cluster"
    echo -e "                Initialize Wazuh indexer cluster security settings."
    echo -e ""
    echo -e "        -t,  --tar <path-to-certs-tar>"
    echo -e "                Path to tar containing certificate files. By default: ${base_path}/wazuh-install-files.tar"
    echo -e ""
    echo -e "        -u,  --uninstall"
    echo -e "                Uninstalls all Wazuh components. This will erase all the existing configuration and data."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete installation output."
    echo -e ""
    echo -e "        -V,  --version"
    echo -e "                Shows the version of the script and Wazuh packages."
    echo -e ""
    echo -e "        -wd,  --wazuh-dashboards <dashboards-node-name>"
    echo -e "                Install and configure Wazuh dashboard."
    echo -e ""
    echo -e "        -wi,  --wazuh-indexer <indexer-node-name>"
    echo -e "                Install and configure Wazuh indexer."
    echo -e ""
    echo -e "        -ws,  --wazuh-server <wazuh-node-name>"
    echo -e "                Install and configure Wazuh server and Filebeat."
    echo -e ""
    echo -e "        -dw,  --download-wazuh <deb|rpm>"
    echo -e "                Download Wazuh Package for Offline Install."
    exit 1

}


function main() {
    umask 177

    common_checkRoot

    if [ -z "${1}" ]; then
        getHelp
    fi

    while [ -n "${1}" ]
    do
        case "${1}" in
            "-a"|"--all-in-one")
                AIO=1
                shift 1
                ;;
            "-ds"|"--disable-spinner")
                disableSpinner=1
                shift 1
                ;;
            "-c"|"--configfile")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <path-to-config-yml> after -c|--configfile"
                    getHelp
                    exit 1
                fi
                file_conf=1
                config_file="${2}"
                shift 2
                ;;
            "-F"|"--force-dashboard")
                force=1
                shift 1
                ;;
            "-g"|"--generate-configurations")
                configurations=1
                shift 1
                ;;
            "-h"|"--help")
                getHelp
                ;;
            "-i"|"--ignore-check")
                ignore=1
                shift 1
                ;;
            "-o"|"--overwrite")
                overwrite=1
                shift 1
                ;;
            "-s"|"--start-cluster")
                start_elastic_cluster=1
                shift 1
                ;;
            "-t"|"--tar")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <path-to-certs-tar> after -t|--tar"
                    getHelp
                    exit 1
                fi
                tar_conf=1
                tar_file="${2}"
                shift 2
                ;;
            "-u"|"--uninstall")
                uninstall=1
                shift 1
                ;;
            "-v"|"--verbose")
                debugEnabled=1
                debug="2>&1 | tee -a ${logfile}"
                shift 1
                ;;
            "-V"|"--version")
                showVersion=1
                shift 1
                ;;
            "-wd"|"--wazuh-dashboard")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <node-name> after -wd|---wazuh-dashboard"
                    getHelp
                    exit 1
                fi
                dashboard=1
                dashname="${2}"
                shift 2
                ;;
            "-wi"|"--wazuh-indexer")
                if [ -z "${2}" ]; then
                    common_logger -e "Arguments contain errors. Probably missing <node-name> after -wi|--wazuh-indexer."
                    getHelp
                    exit 1
                fi
                indexer=1
                indxname="${2}"
                shift 2
                ;;
            "-ws"|"--wazuh-server")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <node-name> after -ws|--wazuh-server"
                    getHelp
                    exit 1
                fi
                wazuh=1
                winame="${2}"
                shift 2
                ;;
            "-dw"|"--download-wazuh")
                if [ -z "${2}" ]; then
                    common_logger -e "Error on arguments. Probably missing <deb|rpm> after -dw|--download-wazuh"
                    getHelp
                    exit 1
                fi
                download=1
                package_type="${2}"
                shift 2
                ;;
            *)
                echo "Unknow option: "${1}""
                getHelp
        esac
    done

    if [ -n "${showVersion}" ]; then
        common_logger "Wazuh version: ${wazuh_version}"
        common_logger "Filebeat version: ${filebeat_version}"
        common_logger "Wazuh installation assistant version: ${wazuh_install_vesion}"
        exit 0
    fi

    if [ -z "${disableSpinner}" ]; then
        installCommon_spin &
        spin_pid=$!
        trap "kill -9 ${spin_pid} > /dev/null 2>&1" EXIT
    fi

    common_logger "Starting Wazuh installation assistant. Wazuh version: ${wazuh_version}"
    common_logger "The verbose logging will be redirected to the file: ${logfile}"

# -------------- Uninstall case  ------------------------------------

    check_dist
    common_checkSystem
    common_checkInstalled
    checks_arguments
    if [ -n "${uninstall}" ]; then
        installCommon_rollBack
        exit 0
    fi

# -------------- Preliminary checks  --------------------------------

    if [ -z "${configurations}" ] && [ -z "${AIO}" ] && [ -z "${download}" ]; then
        checks_previousCertificate
    fi
    checks_arch
    if [ -n "${ignore}" ]; then
        common_logger -w "Hardware and system checks ignored."
    else
        checks_health
    fi
    if [ -n "${AIO}" ] ; then
        rm -f "${tar_file}"
    fi

# -------------- Prerequisites and Wazuh repo  ----------------------
    if [ -n "${AIO}" ] || [ -n "${indexer}" ] || [ -n "${dashboard}" ] || [ -n "${wazuh}" ]; then
        installCommon_installPrerequisites
        installCommon_addWazuhRepo
    fi

# -------------- Configuration creation case  -----------------------

    # Creation certificate case: Only AIO and -g option can create certificates.
    if [ -n "${configurations}" ] || [ -n "${AIO}" ]; then
        common_logger "--- Configuration files ---"
        installCommon_createInstallFiles
    fi

    if [ -z "${configurations}" ] && [ -z "${download}" ]; then
        installCommon_extractConfig
        config_file="/tmp/wazuh-install-files/config.yml"
        cert_readConfig
    fi

    # Distributed architecture: node names must be different
    if [[ -z "${AIO}" && -z "${download}" && ( -n "${indexer}"  || -n "${dashboard}" || -n "${wazuh}" ) ]]; then
        checks_names
    fi

# -------------- Wazuh Indexer case -------------------------------

    if [ -n "${indexer}" ]; then
        common_logger "--- Wazuh indexer ---"
        indexer_install
        indexer_configure
        installCommon_startService "wazuh-indexer"
        indexer_initialize
    fi

# -------------- Start Elasticsearch cluster case  ------------------

    if [ -n "${start_elastic_cluster}" ]; then
        indexer_startCluster
        installCommon_changePasswords
    fi

# -------------- Wazuh Dashboard case  ------------------------------

    if [ -n "${dashboard}" ]; then
        common_logger "--- Wazuh dashboard ----"

        dashboard_install
        dashboard_configure
        installCommon_changePasswords
        installCommon_startService "wazuh-dashboard"
        dashboard_initialize

    fi

# -------------- Wazuh case  ---------------------------------------

    if [ -n "${wazuh}" ]; then
        common_logger "--- Wazuh server ---"

        manager_install
        if [ -n "${server_node_types[*]}" ]; then
            manager_startCluster
        fi
        installCommon_startService "wazuh-manager"
        filebeat_install
        filebeat_configure
        installCommon_changePasswords
        installCommon_startService "filebeat"
    fi

# -------------- AIO case  ------------------------------------------

    if [ -n "${AIO}" ]; then

        common_logger "--- Wazuh indexer ---"
        indexer_install
        indexer_configure
        installCommon_startService "wazuh-indexer"
        indexer_initialize
        common_logger "--- Wazuh server ---"
        manager_install
        installCommon_startService "wazuh-manager"
        filebeat_install
        filebeat_configure
        installCommon_startService "filebeat"
        common_logger "--- Wazuh dashboard ---"
        dashboard_install
        dashboard_configure
        installCommon_startService "wazuh-dashboard"
        installCommon_changePasswords
        dashboard_initializeAIO
    fi

# -------------- Offline case  ------------------------------------------

    if [ -n "${download}" ]; then
        common_logger "--- Download Packages ---"
        offline_download
    fi


# -------------------------------------------------------------------

    if [ -z "${configurations}" ] && [ -z "${download}" ]; then
        installCommon_restoreWazuhrepo
    fi

    if [ -n "${AIO}" ] || [ -n "${indexer}" ] || [ -n "${dashboard}" ] || [ -n "${wazuh}" ]; then
        eval "rm -rf /tmp/wazuh-install-files ${debug}"
        common_logger "Installation finished."
    elif [ -n "${start_elastic_cluster}" ]; then
        common_logger "Elasticsearch cluster started."
    fi

}
