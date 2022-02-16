# Passwords tool - main functions
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function getHelp() {

    echo -e ""
    echo -e "NAME"
    echo -e "        $(basename "${0}") - Manage passwords for OpenDistro users."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "${0}") [OPTIONS]"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --change-all"
    echo -e "                Changes all the Open Distro user passwords and prints them on screen."
    echo -e ""
    echo -e "        -u,  --user <user>"
    echo -e "                Indicates the name of the user whose password will be changed." 
    echo -e "                If no password specified it will generate a random one."
    echo -e ""
    echo -e "        -p,  --password <password>"
    echo -e "                Indicates the new password, must be used with option -u."
    echo -e ""
    echo -e "        -c,  --cert <route-admin-certificate>"
    echo -e "                Indicates route to the admin certificate"
    echo -e ""
    echo -e "        -k,  --certkey <route-admin-certificate-key>"
    echo -e "                Indicates route to the admin certificate key".
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete script execution output".
    echo -e ""
    echo -e "        -f,  --file <password_file.yml>"
    echo -e "                Changes the passwords for the ones given in the file."
    echo -e "                Each user has to have this format."
    echo -e ""
    echo -e "                    User:"
    echo -e "                        name: <user>"
    echo -e "                        password: <password>"
    echo -e ""
    echo -e "        -gf, --generate-file <password_file.yml>"
    echo -e "                Generate password file with random passwords for standard users"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help"
    echo -e ""
    exit 1

}

function main() {

    if [ -n "${1}" ]; then
        while [ -n "${1}" ]
        do
            case "${1}" in
            "-v"|"--verbose")
                verboseenabled=1
                shift 1
                ;;
            "-a"|"--change-all")
                changeall=1
                shift 1
                ;;
            "-u"|"--user")
                nuser=${2}
                shift
                shift
                ;;
            "-p"|"--password")
                password=${2}
                shift
                shift
                ;;
            "-c"|"--cert")
                adminpem=${2}
                shift
                shift
                ;;
            "-k"|"--certkey")
                adminkey=${2}
                shift
                shift
                ;;
            "-f"|"--file")
                p_file=${2}
                shift
                shift
                ;;
            "-gf"|"--generate-file")
                gen_file=${2}
                shift
                shift
                ;;
            "-h"|"--help")
                getHelp
                ;;
            *)
                getHelp
            esac
        done

        export JAVA_HOME=/usr/share/wazuh-indexer/jdk/

        if [ -n "${verboseenabled}" ]; then
            debug="2>&1 | tee -a ${logfile}"
        fi

        if [ -n "${gen_file}" ]; then
            passwords_generatePasswordFile
            if [ -z "${p_file}" ] && [ -z "${nuser}" ] && [ -z "${changeall}" ]; then
                exit 0
            fi
        fi

        common_checkInstalled
        common_checkSystem

        if [ -n "${p_file}" ] && [ ! -f "${p_file}" ]; then
            getHelp
        fi

        if [ -n "${nuser}" ] && [ -n "${changeall}" ]; then
            getHelp
        fi

        if [ -n "${password}" ] && [ -n "${changeall}" ]; then
            getHelp
        fi

        if [ -n "${nuser}" ] && [ -n "${p_file}" ]; then
            getHelp
        fi

        if [ -n "${password}" ] && [ -n "${p_file}" ]; then
            getHelp
        fi

        if [ -z "${nuser}" ] && [ -n "${password}" ]; then
            getHelp
        fi

        if [ -z "${nuser}" ] && [ -z "${password}" ] && [ -z "${changeall}" ] && [ -z  "${p_file}" ]; then
            getHelp
        fi

        if [ -n "${nuser}" ]; then
            passwords_readUsers
            passwords_checkUser
        fi

        if [ -n "${nuser}" ] && [ -z "${password}" ]; then
            autopass=1
            passwords_generatePassword
        fi

        if [ -n "${changeall}" ]; then
            passwords_readUsers
            passwords_generatePassword
        fi

        if [ -n "${p_file}" ] && [ -z "${changeall}" ]; then
            passwords_readUsers
        fi

        if [ -n "${p_file}" ]; then
            passwords_readFileUsers
        fi

        passwords_getNetworkHost
        passwords_createBackUp
        passwords_generateHash
        passwords_changePassword
        passwords_runSecurityAdmin

    else

        getHelp

    fi

}