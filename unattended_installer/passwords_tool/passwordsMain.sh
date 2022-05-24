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
    echo -e "        $(basename "${0}") - Manage passwords for Wazuh indexer users."
    echo -e ""
    echo -e "SYNOPSIS"
    echo -e "        $(basename "${0}") [OPTIONS]"
    echo -e ""
    echo -e "DESCRIPTION"
    echo -e "        -a,  --change-all"
    echo -e "                Changes all the Wazuh indexer user passwords and prints them on screen."
    echo -e ""
    echo -e "        -ai,  --api <currentPassword>"
    echo -e "                Change the Wazuh API password given the current password, it needs --id-api ,--user and --password."
    echo -e "                If not an administrator --admin-user and --admin-password need to be provided."
    echo -e ""
    echo -e "        -au,  --admin-user <adminUser>"
    echo -e "                Admin user for Wazuh API it is needed when the user given it is not an administrator"
    echo -e ""
    echo -e "        -ap,  --admin-password <adminPassword>"
    echo -e "                Password for Wazuh API admin user, it is needed when the user given it is not an administrator"
    echo -e ""
    echo -e "        -id,  --id-api <id>"
    echo -e "                ID for Wazuh API user to be changed"
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
    echo -e "        -f,  --file <passwords.wazuh>"
    echo -e "                Changes the passwords for the ones given in the file."
    echo -e "                Each user has to have this format."
    echo -e ""
    echo -e "                    # Description"
    echo -e "                      username: <user>"
    echo -e "                      password: <password>"
    echo -e ""
    echo -e "        -gf, --generate-file <passwords.wazuh>"
    echo -e "                Generate password file with random passwords for standard users"
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help"
    echo -e ""
    exit 1

}

function main() {

    umask 177

    common_checkRoot

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
            "-A"|"--api")
                api=1
                if [ -z ${2} ]; then
                    echo "Argument --api-id needs a second argument"
                    getHelp
                    exit 1
                fi
                currentPassword=${2}
                shift
                shift
                ;;
            "-au"|"--admin-user")
                adminAPI=1
                if [ -z ${2} ]; then
                    echo "Argument --admin needs a second argument"
                    getHelp
                    exit 1
                fi
                adminUser=${2}
                shift
                shift
                ;;
            "-ap"|"--admin-password")
                if [ -z ${2} ]; then
                    echo "Argument --admin needs a second argument"
                    getHelp
                    exit 1
                fi
                adminPassword=${2}
                shift
                shift
                ;;
            "-id"|"--id-api")
                if [ -z ${2} ]; then
                    echo "Argument --id-api needs a second argument"
                    getHelp
                    exit 1
                fi
                id=${2}
                shift
                shift
                ;;
            "-u"|"--user")
                if [ -z ${2} ]; then
                    echo "Argument --user needs a second argument"
                    getHelp
                    exit 1
                fi
                nuser=${2}
                shift
                shift
                ;;
            "-p"|"--password")
                if [ -z ${2} ]; then
                    echo "Argument --password needs a second argument"
                    getHelp
                    exit 1
                fi
                password=${2}
                shift
                shift
                ;;
            "-c"|"--cert")
                if [ -z ${2} ]; then
                    echo "Argument --cert needs a second argument"
                    getHelp
                    exit 1
                fi
                adminpem=${2}
                shift
                shift
                ;;
            "-k"|"--certkey")
                if [ -z ${2} ]; then
                    echo "Argument --certkey needs a second argument"
                    getHelp
                    exit 1
                fi
                adminkey=${2}
                shift
                shift
                ;;
            "-f"|"--file")
                if [ -z ${2} ]; then
                    echo "Argument --file needs a second argument"
                    getHelp
                    exit 1
                fi
                p_file=${2}
                shift
                shift
                ;;
            "-gf"|"--generate-file")
                if [ -z ${2} ]; then
                    echo "Argument --generate-file needs a second argument"
                    getHelp
                    exit 1
                fi
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

        common_checkSystem
        common_checkInstalled

        if [ -z "${api}" ]; then

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
            if [ -z "${currentPassword}" ] || [ -z "${id}" ] || [ -z "${nuser}" ] || [ -z "${password}" ]; then
                getHelp
                fi

            if [ -n "${adminAPI}" ]; then
                if [ -z "${currentPassword}" ] || [ -z "${id}" ] || [ -z "${nuser}" ] || [ -z "${password}" ] || [ -z "${adminUser}" ] || [ -z "${adminPassword}" ]; then
                getHelp
                fi
            fi
            passwords_changePasswordAPI
        fi
    else
        getHelp
    fi

}