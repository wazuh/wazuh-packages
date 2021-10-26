#!/bin/bash

# Tool to change the passwords of Open Distro internal users
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

VERBOSE='> /dev/null 2>&1'
if [ -n "$(command -v yum)" ]; then
    SYS_TYPE="yum"
elif [ -n "$(command -v zypper)" ]; then
    SYS_TYPE="zypper"   
elif [ -n "$(command -v apt-get)" ]; then
    SYS_TYPE="apt-get"   
fi

## Checks if the script is run with enough privileges

checkRoot() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1;
    fi 
}

restartService() {

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        eval "systemctl restart $1.service ${VERBOSE}"
        if [  "$?" != 0  ]; then
            echo "${1^} could not be started."
            exit 1;
        else
            echo "${1^} started"
        fi  
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        eval "/etc/init.d/$1 restart ${VERBOSE}"
        if [  "$?" != 0  ]; then
            echo "${1^} could not be started."
            exit 1;
        else
            echo "${1^} started"
        fi     
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        eval "/etc/rc.d/init.d/$1 restart ${VERBOSE}"
        if [  "$?" != 0  ]; then
            echo "${1^} could not be started."
            exit 1;
        else
            echo "${1^} started"
        fi             
    else
        echo "Error: ${1^} could not start. No service manager found on the system."
        exit 1;
    fi

}

## Shows script usage
getHelp() {
   echo ""
   echo "Usage: $0 arguments"
   echo -e "\t-a     | --change-all Changes all the Open Distro user passwords and prints them on screen"
   echo -e "\t-u     | --user <user> Indicates the name of the user whose password will be changed. If no password specified it will generate a random one"
   echo -e "\t-p     | --password <password> Indicates the new password, must be used with option -u"
   echo -e "\t-c     | --cert <route-admin-certificate> Indicates route to the admin certificate"
   echo -e "\t-k     | --certkey <route-admin-certificate-key> Indicates route to the admin certificate key"
   echo -e "\t-v     | --verbose Shows the complete script execution output"
   echo -e "\t-f     | --file <password_file.yml> Changes the passwords for the ones given in the file. It has to be formatted like this, with three lines per user: \n\t\tUser:\n\t\t\tname:<user>\n\t\t\tpassword:<password>"
   echo -e "\t-h     | --help Shows help"
   exit 1 # Exit script after printing help
}

## Gets the network host

getNetworkHost() {
    IP=$(grep -hr "network.host:" /etc/elasticsearch/elasticsearch.yml)
    NH="network.host: "
    IP="${IP//$NH}"
    
    if [ ${IP} == "0.0.0.0" ]; then
        IP="localhost"
    fi
}

## Checks if Open Distro for Elasticsearch is installed

checkInstalled() {
    
    if [ "${SYS_TYPE}" == "yum" ]; then
        elasticinstalled=$(yum list installed 2>/dev/null | grep opendistroforelasticsearch)
    elif [ "${SYS_TYPE}" == "zypper" ]; then
        elasticinstalled=$(zypper packages --installed | grep opendistroforelasticsearch | grep i+ | grep noarch)
    elif [ "${SYS_TYPE}" == "apt-get" ]; then
        elasticinstalled=$(apt list --installed  2>/dev/null | grep 'opendistroforelasticsearch*')
    fi 

    if [ -z "${elasticinstalled}" ]; then
        echo "Error: Open Distro is not installed on the system."
        exit 1;
    else
        capem=$(grep "opendistro_security.ssl.transport.pemtrustedcas_filepath: " /etc/elasticsearch/elasticsearch.yml )
        rcapem="opendistro_security.ssl.transport.pemtrustedcas_filepath: "
        capem="${capem//$rcapem}"
        if [[ -z ${adminpem} ]] || [[ -z ${adminkey} ]]; then
            readAdmincerts
        fi
    fi

}

readAdmincerts() {

    if [[ -f /etc/elasticsearch/certs/admin.pem ]]; then
        adminpem="/etc/elasticsearch/certs/admin.pem"
    else
        echo "Error. No admin certificate indicated. Please run the script with the option -c <path-to-certificate>."
        exit 1;
    fi

    if [[ -f /etc/elasticsearch/certs/admin-key.pem ]]; then
        adminkey="/etc/elasticsearch/certs/admin-key.pem"
    elif [[ -f /etc/elasticsearch/certs/admin.key ]]; then
        adminkey="/etc/elasticsearch/certs/admin.key"
    else
        echo "Error. No admin certificate key indicated. Please run the script with the option -k <path-to-key-certificate>."
        exit 1;
    fi    

}

## Reads all the users present in internal_users.yml

readUsers() {
    SUSERS=$(grep -B 1 hash: /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml | grep -v hash: | grep -v "-" | awk '{ print substr( $0, 1, length($0)-1 ) }')
    USERS=($SUSERS)  
}

## Reads all the users and passwords in the given passwords file

readFileUsers() {

    FILECORRECT=$(grep -Pzc '\A(User:\s*name:\s*\w+\s*password:\s*\w+\s*)+\Z' $FILE)
    if [ $FILECORRECT -ne 1 ]; then
	echo "Error: the password file doesn't have a correct format.
It must have this format:
User:
   name: wazuh
   password: wazuhpasword
User:
   name: kibanaserver
   password: kibanaserverpassword"
	exit 1
    fi	

    SFILEUSERS=$(grep name: ${FILE} | awk '{ print substr( $2, 1, length($2) ) }')
    SFILEPASSWORDS=$(grep password: ${FILE} | awk '{ print substr( $2, 1, length($2) ) }')

    FILEUSERS=($SFILEUSERS)
    FILEPASSWORDS=($SFILEPASSWORDS)

    if [ -n "${VERBOSEENABLED}" ]; then
        echo "Users in the file: ${FILEUSERS[@]}"
        echo "Passwords in the file: ${FILEPASSWORDS[@]}"
    fi

    if [ -n "${CHANGEALL}" ]; then
        for i in "${!USERS[@]}"; do
	    for j in "${!FILEUSERS[@]}"; do
	        if [[ ${USERS[i]} == ${FILEUSERS[j]} ]]; then
		    PASSWORDS[i]=${FILEPASSWORDS[j]}
		fi
	    done
        done
    else
	FINALUSERS=()
	FINALPASSWORDS=()

	for j in "${!FILEUSERS[@]}"; do
	    supported=false
	    for i in "${!USERS[@]}"; do
	        if [[ ${USERS[i]} == ${FILEUSERS[j]} ]]; then
		    FINALUSERS+=(${FILEUSERS[j]})
		    FINALPASSWORDS+=(${FILEPASSWORDS[j]})
		    supported=true
		fi
	    done
	    if [ $supported = false ]; then
	        echo "Error: The given user ${FILEUSERS[j]} does not exist"
	    fi
        done

	USERS=()
	USERS=(${FINALUSERS[@]})
	PASSWORDS=(${FINALPASSWORDS[@]})
	CHANGEALL=1
    fi

}

## Checks if the user exists

checkUser() {

    for i in "${!USERS[@]}"; do
        if [ ${USERS[i]} == $NUSER ]; then
            EXISTS=1
        fi
    done

    if [ -z "${EXISTS}" ]; then
        echo "Error: The given user does not exist"
        exit 1;
    fi

}

## Creates a backup of the existing internal_users.yml

createBackUp() {
    
    echo "Creating backup..."
    eval "mkdir /usr/share/elasticsearch/backup ${VERBOSE}"
    eval "cd /usr/share/elasticsearch/plugins/opendistro_security/tools/ ${VERBOSE}"
    eval "./securityadmin.sh -backup /usr/share/elasticsearch/backup -nhnv -cacert ${capem} -cert ${adminpem} -key ${adminkey} -icl -h ${IP} ${VERBOSE}"
    if [  "$?" != 0  ]; then
        echo "Error: The backup could not be created"
        exit 1;
    fi
    echo "Backup created"
    
}

## Generate random password

generatePassword() {

    if [ -n "${NUSER}" ]; then
        echo "Generating random password"
        PASSWORD=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c${1:-32};echo;)
    else
        echo "Generating random passwords"
        for i in "${!USERS[@]}"; do
            PASS=$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c${1:-32};echo;)
            PASSWORDS+=(${PASS})
        done
    fi

        if [  "$?" != 0  ]; then
        echo "Error: The password has not been generated"
        exit 1;
    fi
    echo "Done"
 
}

## Generates the hash for the new password

generateHash() {
    
    if [ -n "${CHANGEALL}" ]; then
        echo "Generating hashes"
        for i in "${!PASSWORDS[@]}"
        do
            NHASH=$(bash /usr/share/elasticsearch/plugins/opendistro_security/tools/hash.sh -p ${PASSWORDS[i]} | grep -v WARNING)
            HASHES+=(${NHASH})
        done
        echo "Hashes generated"
    else
        echo "Generating hash"
        HASH=$(bash /usr/share/elasticsearch/plugins/opendistro_security/tools/hash.sh -p ${PASSWORD} | grep -v WARNING)
        if [  "$?" != 0  ]; then
            echo "Error: Hash generation failed."
            exit 1;
        fi    
        echo "Hash generated"
    fi
}

## Changes the password for the indicated user

changePassword() {
    
    if [ -n "${CHANGEALL}" ]; then
        for i in "${!PASSWORDS[@]}"
        do
           awk -v new=${HASHES[i]} 'prev=="'${USERS[i]}':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/elasticsearch/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /usr/share/elasticsearch/backup/internal_users.yml

            if [ "${USERS[i]}" == "wazuh" ]; then
                wazuhpass=${PASSWORDS[i]}
            elif [ "${USERS[i]}" == "kibanaserver" ]; then
                kibpass=${PASSWORDS[i]}
            fi  

        done
    else
        awk -v new="$HASH" 'prev=="'${NUSER}':"{sub(/\042.*/,""); $0=$0 new} {prev=$1} 1' /usr/share/elasticsearch/backup/internal_users.yml > internal_users.yml_tmp && mv -f internal_users.yml_tmp /usr/share/elasticsearch/backup/internal_users.yml

        if [ "${NUSER}" == "wazuh" ]; then
            wazuhpass=${PASSWORD}
        elif [ "${NUSER}" == "kibanaserver" ]; then
            kibpass=${PASSWORD}
        fi        

    fi
    
    if [ "${NUSER}" == "wazuh" ] || [ -n "${CHANGEALL}" ]; then

        if [ "${SYS_TYPE}" == "yum" ]; then
            hasfilebeat=$(yum list installed 2>/dev/null | grep filebeat)
        elif [ "${SYS_TYPE}" == "zypper" ]; then
            hasfilebeat=$(zypper packages --installed | grep filebeat | grep i+ | grep noarch)
        elif [ "${SYS_TYPE}" == "apt-get" ]; then
            hasfilebeat=$(apt list --installed  2>/dev/null | grep filebeat)
        fi 

        if [ "${SYS_TYPE}" == "yum" ]; then
            haskibana=$(yum list installed 2>/dev/null | grep opendistroforelasticsearch-kibana)
        elif [ "${SYS_TYPE}" == "zypper" ]; then
            haskibana=$(zypper packages --installed | grep opendistroforelasticsearch-kibana | grep i+)
        elif [ "${SYS_TYPE}" == "apt-get" ]; then
            haskibana=$(apt list --installed  2>/dev/null | grep opendistroforelasticsearch-kibana)
        fi     

        wazuhold=$(grep "password:" /etc/filebeat/filebeat.yml )
        ra="  password: "
        wazuhold="${wazuhold//$ra}"

        wazuhkibold=$(grep "password:" /etc/kibana/kibana.yml )
        rk="elasticsearch.password: "
        wazuhkibold="${wazuhkibold//$rk}"        

        if [ -n "${hasfilebeat}" ]; then
            conf="$(awk '{sub("  password: '${wazuhold}'", "  password: '${wazuhpass}'")}1' /etc/filebeat/filebeat.yml)"
            echo "${conf}" > /etc/filebeat/filebeat.yml  
            restartService "filebeat"
        fi 
    fi
        if [ -n "${haskibana}" ] && [ -n "${kibpass}" ]; then
            conf="$(awk '{sub("elasticsearch.password: '${wazuhkibold}'", "elasticsearch.password: '${kibpass}'")}1' /etc/kibana/kibana.yml)"
            echo "${conf}" > /etc/kibana/kibana.yml 
            restartService "kibana"
        fi         

}

## Runs the Security Admin script to load the changes
runSecurityAdmin() {
    
    echo "Loading changes..."
    eval "cp /usr/share/elasticsearch/backup/* /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ ${VERBOSE}"
    eval "cd /usr/share/elasticsearch/plugins/opendistro_security/tools/ ${VERBOSE}"
    eval "./securityadmin.sh -cd ../securityconfig/ -nhnv -cacert ${capem} -cert ${adminpem} -key ${adminkey} -icl -h ${IP} ${VERBOSE}"
    if [  "$?" != 0  ]; then
        echo "Error: Could not load the changes."
        exit 1;
    fi    
    eval "rm -rf /usr/share/elasticsearch/backup/ ${VERBOSE}"
    echo "Done"

    if [[ -n "${NUSER}" ]] && [[ -n ${AUTOPASS} ]]; then
        echo $'\nThe password for user '${NUSER}' is '${PASSWORD}''
        echo "Password changed. Remember to update the password in /etc/filebeat/filebeat.yml and /etc/kibana/kibana.yml if necessary and restart the services."
    fi

    if [[ -n "${NUSER}" ]] && [[ -z ${AUTOPASS} ]]; then
        echo "Password changed. Remember to update the password in /etc/filebeat/filebeat.yml and /etc/kibana/kibana.yml if necessary and restart the services."
    fi    

    if [ -n "${CHANGEALL}" ]; then
        
        for i in "${!USERS[@]}"
        do
            echo ""
            echo "The password for ${USERS[i]} is ${PASSWORDS[i]}"
        done
        echo ""
        echo "Passwords changed. Remember to update the password in /etc/filebeat/filebeat.yml and /etc/kibana/kibana.yml if necessary and restart the services."
        echo ""
    fi 

}

main() {   

    if [ -n "$1" ]; then      
        while [ -n "$1" ]
        do
            case "$1" in
            "-v"|"--verbose")
                VERBOSEENABLED=1
                shift 1
                ;;
            "-a"|"--change-all")
                CHANGEALL=1
                shift 1
                ;;                
            "-u"|"--user")
                NUSER=$2
                shift
                shift
                ;;
            "-p"|"--password")
                PASSWORD=$2
                shift
                shift
                ;;
            "-c"|"--cert")
                adminpem=$2
                shift
                shift
                ;; 
            "-k"|"--certkey")
                adminkey=$2
                shift
                shift
                ;; 
	"-f"|"--file")
		FILE=$2
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

        export JAVA_HOME=/usr/share/elasticsearch/jdk/
        
        if [ -n "${VERBOSEENABLED}" ]; then
            VERBOSE=""
        fi 

        checkInstalled   

	if [ -n "${FILE}" ] && [ ! -f "${FILE}" ]; then
	    getHelp
	fi

        if [ -n "${NUSER}" ] && [ -n "${CHANGEALL}" ]; then
            getHelp
        fi 

        if [ -n "${PASSWORD}" ] && [ -n "${CHANGEALL}" ]; then
            getHelp
        fi 

        if [ -n "${NUSER}" ] && [ -n "${FILE}" ]; then
            getHelp
        fi 

        if [ -n "${PASSWORD}" ] && [ -n "${FILE}" ]; then
            getHelp
        fi         

        if [ -z "${NUSER}" ] && [ -n "${PASSWORD}" ]; then
            getHelp
        fi   

        if [ -z "${NUSER}" ] && [ -z "${PASSWORD}" ] && [ -z "${CHANGEALL}" ] && [ -z  "${FILE}" ]; then
            getHelp
        fi 

        if [ -n "${NUSER}" ]; then
            readUsers
            checkUser
        fi          

        if [ -n "${NUSER}" ] && [ -z "${PASSWORD}" ]; then
            AUTOPASS=1
            generatePassword
        fi

        if [ -n "${CHANGEALL}" ]; then
            readUsers
            generatePassword
        fi               

        if [ -n "${FILE}" ] && [ -z "${CHANGEALL}" ]; then
	    readUsers
	fi	    

	if [ -n "${FILE}" ]; then
	    readFileUsers
	fi  

        getNetworkHost
        createBackUp
        generateHash
        changePassword
        runSecurityAdmin

    else

        getHelp        

    fi

}

main "$@"
