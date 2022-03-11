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
                    common_logger -e "Error on arguments. Probably missing <path-to-config-yml> after -f|--fileconfig"
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
                    common_logger -e "Error on arguments. Probably missing <node-name> after -w|--wazuh-server"
                    getHelp
                    exit 1
                fi
                wazuh=1
                winame="${2}"
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
        trap "kill -9 ${spin_pid} ${debug}" EXIT
    fi

    common_logger "Starting Wazuh installation assistant. Wazuh version: ${wazuh_version}"

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

    if [ -z "${configurations}" ] && [ -z "${AIO}" ]; then
        checks_previousCertificate
    fi
    checks_arch
    if [ -n "${ignore}" ]; then
        common_logger -w "Health-check ignored."
    else
        checks_health
    fi
    if [ -n "${AIO}" ] ; then
        rm -f "${tar_file}"
    fi

# -------------- Configuration creation case  -----------------------

    # Creation certificate case: Only AIO and -c option can create certificates.
    if [ -n "${configurations}" ] || [ -n "${AIO}" ]; then
        common_logger "--- Configuration files ---"
        common_logger "Generating configuration files."
        if [ -n "${configurations}" ]; then
            cert_checkOpenSSL
        fi
        installCommon_createCertificates
        if [ -n "${server_node_types[*]}" ]; then
            installCommon_createClusterKey
        fi
        gen_file="${base_path}/certs/password_file.yml"
        passwords_generatePasswordFile
        # Using cat instead of simple cp because OpenSUSE unknown error.
        eval "cat '${config_file}' > '${base_path}/certs/config.yml'"
        eval "chown root:root ${base_path}/certs/*"
        eval "tar -zcf '${tar_file}' -C '${base_path}/certs/' . ${debug}"
        eval "rm -rf '${base_path}/certs' ${debug}"
        common_logger "Created ${tar_file}. Contains Wazuh cluster key, certificates, and passwords necessary for installation."
    fi

    if [ -z "${configurations}" ]; then
        installCommon_extractConfig
        cert_readConfig
        rm -f "${config_file}"
    fi

    # Distributed architecture: node names must be different
    if [[ -z "${AIO}" && ( -n "${indexer}"  || -n "${dashboard}" || -n "${wazuh}" )]]; then
        checks_names
    fi

# -------------- Prerequisites and Wazuh repo  ----------------------
    if [ -n "${AIO}" ] || [ -n "${indexer}" ] || [ -n "${dashboard}" ] || [ -n "${wazuh}" ]; then
        installCommon_installPrerequisites
        installCommon_addWazuhRepo
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

# -------------------------------------------------------------------

    if [ -z "${configurations}" ]; then
        installCommon_restoreWazuhrepo
    fi

    if [ -n "${AIO}" ] || [ -n "${indexer}" ] || [ -n "${dashboard}" ] || [ -n "${wazuh}" ]; then
        common_logger "Installation finished."
        common_logger "The certificates and passwords used are stored in ${tar_file}."
    elif [ -n "${start_elastic_cluster}" ]; then
        common_logger "Elasticsearch cluster started."
        common_logger "The certificates and passwords used are stored in ${tar_file}."
    fi

}
