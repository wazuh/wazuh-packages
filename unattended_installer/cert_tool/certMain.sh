# Certificate tool - Main functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        wazuh-cert-tool.sh - Manages the creation of certificates of the Wazuh components."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        wazuh-cert-tool.sh [OPTIONS]"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --admin-certificates </path/to/root-ca.pem> </path/to/root-ca.key>"
    echo -e "                Creates the admin certificates, add root-ca.pem and root-ca.key or leave it empty so we can create a new one."
    echo -e ""
    echo -e "        -ca, --root-ca-certificates"
    echo -e "                Creates the root-ca certificates."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Enables verbose mode."
    echo -e ""
    echo -e "        -wd,  --wazuh-dashboard-certificates </path/to/root-ca.pem> </path/to/root-ca.key>"
    echo -e "                Creates the Wazuh dashboard certificates, add root-ca.pem and root-ca.key or leave it empty so we can create a new one."
    echo -e ""
    echo -e "        -wi,  --wazuh-indexer-certificates </path/to/root-ca.pem> </path/to/root-ca.key>"
    echo -e "                Creates the Wazuh indexer certificates, add root-ca.pem and root-ca.key or leave it empty so we can create a new one."
    echo -e ""
    echo -e "        -ws,  --wazuh-server-certificates </path/to/root-ca.pem> </path/to/root-ca.key>"
    echo -e "                Creates the Wazuh server certificates, add root-ca.pem and root-ca.key or leave it empty so we can create a new one."
    echo -e ""
    echo -e "        --all </path/to/root-ca.pem> </path/to/root-ca.key>"
    echo -e "                Creates Wazuh server, Wazuh indexer, Wazuh dashboard, and admin certificates, add root-ca.pem and root-ca.key or leave it empty so we can create a new one."

    exit 1

}

function main() {

    umask 177

    common_checkRoot
    cert_checkOpenSSL

    if [ -n "${1}" ]; then
        while [ -n "${1}" ]
        do
            case "${1}" in
            "-a"|"--admin-certificates")
                if  [[ -n "${2}" ]]; then
                    #Validate that the user has entered the 2 files
                    if [[ -z ${3} ]]; then
                        if [[ ${2} == *".key" ]]; then
                            common_logger -e "You have not entered a root-ca.pem"
                            exit 1
                        else
                            common_logger -e "You have not entered a root-ca.key" 
                            exit 1
                        fi
                    fi
                    cadmin=1
                    rootca="${2}"
                    rootcakey="${3}"
                    shift 3
                else
                    cadmin=1
                    shift 1
                fi
                ;;
            "-ca"|"--root-ca-certificate")
                ca=1
                shift 1
                ;;
            "-h"|"--help")
                getHelp
                ;;
            "-v"|"--verbose")
                debugEnabled=1
                shift 1
                ;;
            "-wd"|"--wazuh-dashboard-certificates")
                if  [[ -n "${2}" ]]; then
                    #Validate that the user has entered the 2 files
                    if [[ -z ${3} ]]; then
                        if [[ ${2} == *".key" ]]; then
                            common_logger -e "You have not entered a root-ca.pem"
                            exit 1
                        else
                            common_logger -e "You have not entered a root-ca.key" 
                            exit 1
                        fi
                    fi
                    cdashboard=1
                    rootca="${2}"
                    rootcakey="${3}"
                    shift 3
                else
                    cdashboard=1
                    shift 1
                fi
                ;;
            "-wi"|"--wazuh-indexer-certificates")
                if  [[ -n "${2}" ]]; then
                    #Validate that the user has entered the 2 files
                    if [[ -z ${3} ]]; then
                        if [[ ${2} == *".key" ]]; then
                            common_logger -e "You have not entered a root-ca.pem"
                            exit 1
                        else
                            common_logger -e "You have not entered a root-ca.key" 
                            exit 1
                        fi
                    fi
                    cindexer=1
                    rootca="${2}"
                    rootcakey="${3}"
                    shift 3
                else
                    cindexer=1
                    shift 1
                fi
                ;;
            "-ws"|"--wazuh-server-certificates")
                if  [[ -n "${2}" ]]; then
                    #Validate that the user has entered the 2 files
                    if [[ -z ${3} ]]; then
                        if [[ ${2} == *".key" ]]; then
                            common_logger -e "You have not entered a root-ca.pem"
                            exit 1
                        else
                            common_logger -e "You have not entered a root-ca.key" 
                            exit 1
                        fi
                    fi
                    cserver=1
                    rootca="${2}"
                    rootcakey="${3}"
                    shift 3
                else
                    cserver=1
                    shift 1
                fi
                ;;
            "--all")
                if  [[ -n "${2}" ]]; then
                    #Validate that the user has entered the 2 files
                    if [[ -z ${3} ]]; then
                        if [[ ${2} == *".key" ]]; then
                            common_logger -e "You have not entered a root-ca.pem"
                            exit 1
                        else
                            common_logger -e "You have not entered a root-ca.key" 
                            exit 1
                        fi
                    fi
                    all=1
                    rootca="${2}"
                    rootcakey="${3}"
                    shift 3
                else
                    all=1
                    shift 1
                fi
                ;;
            *)
                echo "Unknow option: "${1}""
                getHelp
            esac
        done

        if [[ -d ${base_path}/certs ]]; then
            if [ ! -z "$(ls -A ${base_path}/certs)" ]; then
                common_logger -e "Directory ${base_path}/certs already exists. Please, remove the certs directory to create new certificates."
            exit 1
            fi
        else
            eval "mkdir ${base_path}/certs"
        fi

        cert_readConfig

        if [ -n "${debugEnabled}" ]; then
            debug="2>&1 | tee -a ${logfile}"
        fi

        if [[ -n "${cadmin}" ]]; then
            cert_checkRootCA
            cert_generateAdmincertificate
            common_logger "Admin certificates created."
        fi

        if [[ -n "${ca}" ]]; then
            cert_generateRootCAcertificate
            common_logger "Authority certificates created."
        fi

        if [[ -n "${cindexer}" ]]; then
            cert_checkRootCA
            cert_generateIndexercertificates
            common_logger "Wazuh indexer certificates created."
        fi

        if [[ -n "${cserver}" ]]; then
            cert_checkRootCA
            cert_generateFilebeatcertificates
            common_logger "Wazuh server certificates created."
        fi

        if [[ -n "${cdashboard}" ]]; then
            cert_checkRootCA
            cert_generateDashboardcertificates
            common_logger "Wazuh dashboard certificates created."
        fi

        if [[ -n "${all}" ]]; then
            cert_checkRootCA
            cert_generateAdmincertificate
            common_logger "Admin certificates created."
            cert_generateIndexercertificates
            common_logger "Wazuh indexer certificates created."
            cert_generateFilebeatcertificates
            common_logger "Wazuh server certificates created."
            cert_generateDashboardcertificates
            common_logger "Wazuh dashboard certificates created."
        fi

    else
        getHelp
    fi

}