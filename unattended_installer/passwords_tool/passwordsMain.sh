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
    echo -e "                Changes all the Wazuh indexer and Wazuh API user passwords and prints them on screen."
    echo -e "                To change API passwords -au|--admin-user and -ap|--admin-password are required."
    echo -e ""
    echo -e "        -A,  --api"
    echo -e "                Change the Wazuh API password."
    echo -e "                Requires -u|--user, and -p|--password, -au|--admin-user and -ap|--admin-password."
    echo -e ""
    echo -e "        -au,  --admin-user <adminUser>"
    echo -e "                Admin user for Wazuh API, Required to change Wazuh API passwords."
    echo -e "                Requires -A|--api."
    echo -e ""
    echo -e "        -ap,  --admin-password <adminPassword>"
    echo -e "                Password for Wazuh API admin user, Required to change Wazuh API passwords."
    echo -e "                Requires -A|--api."
    echo -e ""
    echo -e "        -u,  --user <user>"
    echo -e "                Indicates the name of the user whose password will be changed."
    echo -e "                If no password specified it will generate a random one."
    echo -e ""
    echo -e "        -p,  --password <password>"
    echo -e "                Indicates the new password, must be used with option -u."
    echo -e ""
    echo -e "        -c,  --cert <route-admin-certificate>"
    echo -e "                Indicates route to the admin certificate."
    echo -e ""
    echo -e "        -k,  --certkey <route-admin-certificate-key>"
    echo -e "                Indicates route to the admin certificate key."
    echo -e ""
    echo -e "        -v,  --verbose"
    echo -e "                Shows the complete script execution output."
    echo -e ""
    echo -e "        -f,  --file <wazuh-passwords.txt>"
    echo -e "                Changes the passwords for the ones given in the file."
    echo -e ""
    echo -e "                Wazuh indexer users must have this format:"
    echo -e ""
    echo -e "                    # Description"
    echo -e "                      indexer_username: <user>"
    echo -e "                      indexer_password: <password>"
    echo -e ""
    echo -e "                Wazuh API users must have this format:"
    echo -e ""
    echo -e "                    # Description"
    echo -e "                      api_username: <user>"
    echo -e "                      api_password: <password>"
    echo -e ""
    echo -e "        -gf, --generate-file <wazuh-passwords.txt>"
    echo -e "                Generate password file with random passwords for standard users."
    echo -e ""
    echo -e "        -h,  --help"
    echo -e "                Shows help."
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
                shift 1
                ;;
            "-au"|"--admin-user")
                if [ -z "${2}" ]; then
                    echo "Argument au|--admin-user needs a second argument"
                    getHelp
                    exit 1
                fi
                adminUser=${2}
                shift 2
                ;;
            "-ap"|"--admin-password")
                if [ -z "${2}" ]; then
                    echo "Argument -ap|--admin-password needs a second argument"
                    getHelp
                    exit 1
                fi
                adminPassword=${2}
                shift 2
                ;;
            "-u"|"--user")
                if [ -z "${2}" ]; then
                    echo "Argument --user needs a second argument"
                    getHelp
                    exit 1
                fi
                nuser=${2}
                shift 2
                ;;
            "-p"|"--password")
                if [ -z "${2}" ]; then
                    echo "Argument --password needs a second argument"
                    getHelp
                    exit 1
                fi
                password=${2}
                shift 2
                ;;
            "-c"|"--cert")
                if [ -z "${2}" ]; then
                    echo "Argument --cert needs a second argument"
                    getHelp
                    exit 1
                fi
                adminpem=${2}
                shift 2
                ;;
            "-k"|"--certkey")
                if [ -z "${2}" ]; then
                    echo "Argument --certkey needs a second argument"
                    getHelp
                    exit 1
                fi
                adminkey=${2}
                shift 2
                ;;
            "-f"|"--file")
                if [ -z "${2}" ]; then
                    echo "Argument --file needs a second argument"
                    getHelp
                    exit 1
                fi
                p_file=${2}
                shift 2
                ;;
            "-gf"|"--generate-file")
                if [ -z "${2}" ]; then
                    echo "Argument --generate-file needs a second argument"
                    getHelp
                    exit 1
                fi
                gen_file=${2}
                shift 2
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

        if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ] && [ -z "${api}" ]; then
            getHelp
        fi

        if [ -n "${nuser}" ]; then
            if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
                passwords_getApiToken
                passwords_getApiUsers
                passwords_getApiIds
            elif [ -z "${wazuh_installed}" ] && [ -n "${dashboard_installed}" ]; then
                passwords_readDashboardUsers
            elif [ -n "${indexer_installed}" ] || [ -n "${wazuh_installed}" ]; then
                passwords_readUsers
            fi
            passwords_checkUser
        fi

        if [ -n "${nuser}" ] && [ -z "${password}" ]; then
            autopass=1
            passwords_generatePassword
        fi

        if [ -n "${nuser}" ] && [ -n "${password}" ]; then
            passwords_checkPassword "${password}"
        fi
        

        if [ -n "${changeall}" ] || [ -n "${p_file}" ]; then
            if [ -n "${indexer_installed}" ] || [ -n "${wazuh_installed}" ]; then
                passwords_readUsers
            fi

            if [ -n "${wazuh_installed}" ]; then
                if [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; then
                    passwords_getApiToken
                    passwords_getApiUsers
                    passwords_getApiIds
                else
                    common_logger "Wazuh API admin credentials not provided, Wazuh API passwords not changed."
                fi
            elif  [ -n "${dashboard_installed}" ]; then
                passwords_readDashboardUsers
            fi
            if [ -n "${changeall}" ]; then
                passwords_generatePassword
            fi
        fi


        if [ -n "${p_file}" ]; then
            passwords_readFileUsers
        fi

        if { [ -z "${api}" ] || [ -n "${changeall}" ]; } && [ -n "${indexer_installed}" ]; then
            passwords_getNetworkHost
            passwords_generateHash
            passwords_changePassword
            passwords_runSecurityAdmin
        fi

        # Call the function to change the password for filebeat and/or kibanaserver
        if [ -z "${indexer_installed}" ] && { [ -n "${wazuh_installed}" ] || [ -n "${dashboard_installed}" ]; }; then
            passwords_changePassword
        fi

        if [ -n "${api}" ] || [ -n "${changeall}" ]; then
            if { [ -n "${adminUser}" ] && [ -n "${adminPassword}" ]; } || { [ -z "${wazuh_installed}" ] && [ -n "${dashboard_installed}" ]; }; then
                passwords_changePasswordApi

            fi
        fi

    else
        getHelp
    fi

}