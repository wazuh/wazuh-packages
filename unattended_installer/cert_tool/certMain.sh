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
    echo -e "        -a,  --admin-certificates"
    echo -e "                Creates the admin certificates."
    echo -e ""
    echo -e "        -ca, --root-ca-certificates"
    echo -e "                Creates the root-ca certificates."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Enables verbose mode."
    echo -e ""
    echo -e "        -wd,  --wazuh-dashboard-certificates"
    echo -e "                Creates the Wazuh dashboard certificates."
    echo -e ""
    echo -e "        -wi,  --wazuh-indexer-certificates"
    echo -e "                Creates the Wazuh indexer certificates."
    echo -e ""
    echo -e "        -ws,  --wazuh-server-certificates"
    echo -e "                Creates the Wazuh server certificates."
    echo -e ""
    echo -e "        --all  "
    echo -e "                Creates Wazuh server, Wazuh indexer, Wazuh dashboard, and admin certificates"

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
                cadmin=1
                shift 1
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
                cdashboard=1
                shift 1
                ;;
            "-wi"|"--wazuh-indexer-certificates")
                cindexer=1
                shift 1
                ;;
            "-ws"|"--wazuh-server-certificates")
                cserver=1
                shift 1
                ;;
            "--all")
                all=1
                shift 1
                ;;
            *)
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
            common_logger "If you have a root-ca enter it as follows /path/to/root-ca.pem and /path/to/root-ca.key, otherwise leave it empty so we can create a new one"
            read -p 'root-ca.pem: ' rootca
            cert_checkRootCA
            cert_generateAdmincertificate
            common_logger "Admin certificates created."
        fi

        if [[ -n "${ca}" ]]; then
            cert_generateRootCAcertificate
            common_logger "Authority certificates created."
        fi

        if [[ -n "${cindexer}" ]]; then
            common_logger "If you have a root-ca enter it as follows /path/to/root-ca.pem and /path/to/root-ca.key, otherwise leave it empty so we can create a new one"
            read -p 'root-ca.pem: ' rootca
            cert_checkRootCA
            cert_generateIndexercertificates
            common_logger "Wazuh indexer certificates created."
        fi

        if [[ -n "${cserver}" ]]; then
            common_logger "If you have a root-ca enter it as follows /path/to/root-ca.pem and /path/to/root-ca.key, otherwise leave it empty so we can create a new one"
            read -p 'root-ca.pem: ' rootca
            cert_checkRootCA
            cert_generateFilebeatcertificates
            common_logger "Wazuh server certificates created."
        fi

        if [[ -n "${cdashboard}" ]]; then
            common_logger "If you have a root-ca enter it as follows /path/to/root-ca.pem and /path/to/root-ca.key, otherwise leave it empty so we can create a new one"
            read -p 'root-ca.pem: ' rootca
            cert_checkRootCA
            cert_generateDashboardcertificates
            common_logger "Wazuh dashboard certificates created."
        fi

        if [[ -n "${all}" ]]; then
            common_logger "If you have a root-ca enter it as follows /path/to/root-ca.pem and /path/to/root-ca.key, otherwise leave it empty so we can create a new one"
            read -p 'root-ca.pem: ' rootca
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