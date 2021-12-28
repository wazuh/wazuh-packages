#!/bin/bash

# Program to install Wazuh manager along Open Distro for Elasticsearch
# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

## Check if system is based on yum or apt-get
char="."
debug='>> /var/log/wazuh-unattended-installation.log 2>&1'
WAZUH_MAJOR="4.2"
WAZUH_VER="4.2.5"
WAZUH_REV="1"
ELK_VER="7.10.2"
OD_VER="1.13.2"
OD_REV="1"
WAZUH_KIB_PLUG_REV="1"
ow=""
repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
repobaseurl="https://packages.wazuh.com/4.x"
resources="https://packages.wazuh.com/resources/${WAZUH_MAJOR}"

if [ -n "$(command -v yum)" ]; then
    sys_type="yum"
    sep="-"
elif [ -n "$(command -v zypper)" ]; then
    sys_type="zypper"   
    sep="-"  
elif [ -n "$(command -v apt-get)" ]; then
    sys_type="apt-get"   
    sep="="
fi

## Prints information
logger() {

    now=$(date +'%m/%d/%Y %H:%M:%S')
    case $1 in 
        "-e")
            mtype="ERROR:"
            message="$2"
            ;;
        "-w")
            mtype="WARNING:"
            message="$2"
            ;;
        *)
            mtype="INFO:"
            message="$1"
            ;;
    esac
    echo $now $mtype $message
}

rollBack() {

    if [ -z "${uninstall}" ]; then
        logger -w "Cleaning the installation" 
    fi   
    
    if [ -n "${wazuhinstalled}" ]; then
        logger -w "Removing the Wazuh manager..."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-manager -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-manager ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge wazuh-manager -y ${debug}"
        fi 
        eval "rm -rf /var/ossec/ ${debug}"
    fi     

    if [ -n "${elasticinstalled}" ]; then
        logger -w "Removing Elasticsearch..."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove opendistroforelasticsearch -y ${debug}"
            eval "yum remove elasticsearch* -y ${debug}"
            eval "yum remove opendistro-* -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove opendistroforelasticsearch elasticsearch* opendistro-* ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge opendistroforelasticsearch elasticsearch* opendistro-* -y ${debug}"
        fi 
        eval "rm -rf /var/lib/elasticsearch/ ${debug}"
        eval "rm -rf /usr/share/elasticsearch/ ${debug}"
        eval "rm -rf /etc/elasticsearch/ ${debug}"
        eval "rm -rf ~/search-guard-tlstool-1.8.zip ${debug}"
        eval "rm -rf ~/searchguard ${debug}"
    fi

    if [ -n "${filebeatinstalled}" ]; then
        logger -w "Removing Filebeat..."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove filebeat -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove filebeat ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge filebeat -y ${debug}"
        fi 
        eval "rm -rf /var/lib/filebeat/ ${debug}"
        eval "rm -rf /usr/share/filebeat/ ${debug}"
        eval "rm -rf /etc/filebeat/ ${debug}"
    fi

    if [ -n "${kibanainstalled}" ]; then
        logger -w "Removing Kibana..."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove opendistroforelasticsearch-kibana -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove opendistroforelasticsearch-kibana ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge opendistroforelasticsearch-kibana -y ${debug}"
        fi 
        eval "rm -rf /var/lib/kibana/ ${debug}"
        eval "rm -rf /usr/share/kibana/ ${debug}"
        eval "rm -rf /etc/kibana/ ${debug}"
    fi

    if [ -z "${uninstall}" ]; then    
        logger -w "Installation cleaned. Check the /var/log/wazuh-unattended-installation.log file to learn more about the issue."
    fi

}

checkArch() {

    arch=$(uname -m)

    if [ ${arch} != "x86_64" ]; then
        logger -e "Uncompatible system. This script must be run on a 64-bit system."
        exit 1;
    fi
    
}

applyLog4j2Mitigation(){

    eval "curl -so /tmp/apache-log4j-2.17.1-bin.tar.gz https://packages.wazuh.com/utils/log4j/apache-log4j-2.17.1-bin.tar.gz ${debug}"
    eval "tar -xf /tmp/apache-log4j-2.17.1-bin.tar.gz -C /tmp/"

    eval "cp /tmp/apache-log4j-2.17.1-bin/log4j-api-2.17.1.jar /usr/share/elasticsearch/lib/  ${debug}"
    eval "cp /tmp/apache-log4j-2.17.1-bin/log4j-core-2.17.1.jar /usr/share/elasticsearch/lib/ ${debug}"
    eval "cp /tmp/apache-log4j-2.17.1-bin/log4j-slf4j-impl-2.17.1.jar /usr/share/elasticsearch/plugins/opendistro_security/ ${debug}"
    eval "cp /tmp/apache-log4j-2.17.1-bin/log4j-api-2.17.1.jar /usr/share/elasticsearch/performance-analyzer-rca/lib/ ${debug}"
    eval "cp /tmp/apache-log4j-2.17.1-bin/log4j-core-2.17.1.jar /usr/share/elasticsearch/performance-analyzer-rca/lib/ ${debug}"

    eval "rm -f /usr/share/elasticsearch/lib//log4j-api-2.11.1.jar ${debug}"
    eval "rm -f /usr/share/elasticsearch/lib/log4j-core-2.11.1.jar ${debug}"
    eval "rm -f /usr/share/elasticsearch/plugins/opendistro_security/log4j-slf4j-impl-2.11.1.jar ${debug}"
    eval "rm -f /usr/share/elasticsearch/performance-analyzer-rca/lib/log4j-api-2.13.0.jar ${debug}"
    eval "rm -f /usr/share/elasticsearch/performance-analyzer-rca/lib/log4j-core-2.13.0.jar ${debug}"

    eval "rm -rf /tmp/apache-log4j-2.17.1-bin ${debug}"
    eval "rm -f /tmp/apache-log4j-2.17.1-bin.tar.gz ${debug}"

}

startService() {

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable $1.service ${debug}"
        eval "systemctl start $1.service ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi  
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        eval "chkconfig $1 on ${debug}"
        eval "service $1 start ${debug}"
        eval "/etc/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi     
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        eval "/etc/rc.d/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "${1^} could not be started."
            rollBack
            exit 1;
        else
            logger "${1^} started"
        fi             
    else
        logger -e "${1^} could not start. No service manager found on the system."
        exit 1;
    fi

}

## Show script usage
getHelp() {

   echo ""
   echo "Usage: $0 arguments"
   echo -e "\t-o   | --overwrite Overwrite the existing installation"
   echo -e "\t-r   | --uninstall Remove the installation"
   echo -e "\t-v   | --verbose Shows the complete installation output"
   echo -e "\t-i   | --ignore-health-check Ignores the health-check"
   echo -e "\t-h   | --help Shows help"
   exit 1 # Exit script after printing help

}

## Install the required packages for the installation
installPrerequisites() {
    logger "Installing all necessary utilities for the installation..."

    if [ ${sys_type} == "yum" ]; then
        eval "yum install curl unzip wget libcap -y ${debug}"
    elif [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install curl unzip wget ${debug}"         
        eval "zypper -n install libcap-progs ${debug} || zypper -n install libcap2 ${debug}"
    elif [ ${sys_type} == "apt-get" ]; then
        eval "apt-get update -q $debug"
        eval "apt-get install apt-transport-https curl unzip wget libcap2-bin -y ${debug}"        
    fi

    if [  "$?" != 0  ]; then
        logger -e "Prerequisites could not be installed"
        exit 1;
    else
        logger "Done"
    fi          
}


## Add the Wazuh repository
addWazuhrepo() {
    logger "Adding the Wazuh repository..."

    if [ ${sys_type} == "yum" ]; then
        eval "rpm --import ${repogpg} ${debug}"
        eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo ${debug}"
    elif [ ${sys_type} == "zypper" ]; then
        eval "rpm --import ${repogpg} ${debug}"
        eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-\$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/zypp/repos.d/wazuh.repo ${debug}"            
    elif [ ${sys_type} == "apt-get" ]; then
        eval "curl -s ${repogpg} --max-time 300 | apt-key add - ${debug}"
        eval "echo "deb '${repobaseurl}'/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list ${debug}"
        eval "apt-get update -q ${debug}"
    fi    

    logger "Done" 
}

## Wazuh manager
installWazuh() {
    
    logger "Installing the Wazuh manager..."
    if [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install wazuh-manager=${WAZUH_VER}-${WAZUH_REV} ${debug}"
    else
        eval "${sys_type} install wazuh-manager${sep}${WAZUH_VER}-${WAZUH_REV} -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Wazuh installation failed"
        rollBack
        exit 1;
    else
        wazuhinstalled="1"
        logger "Done"
    fi   
    startService "wazuh-manager"

}

## Elasticsearch
installElasticsearch() {

    logger "Installing Open Distro for Elasticsearch..."

    if [ ${sys_type} == "yum" ]; then
        eval "yum install opendistroforelasticsearch-${OD_VER}-${OD_REV} -y ${debug}"
    elif [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install opendistroforelasticsearch=${OD_VER}-${OD_REV} ${debug}"
    elif [ ${sys_type} == "apt-get" ]; then
        eval "apt install elasticsearch-oss opendistroforelasticsearch -y ${debug}"
    fi

    if [  "$?" != 0  ]; then
        logger -e "Elasticsearch installation failed"
        rollBack
        exit 1;
    else
        elasticinstalled="1"
        logger "Done"

        logger "Configuring Elasticsearch..."

        eval "curl -so /etc/elasticsearch/elasticsearch.yml ${resources}/open-distro/elasticsearch/7.x/elasticsearch_unattended.yml --max-time 300 ${debug}"
        eval "curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml ${resources}/open-distro/elasticsearch/roles/roles.yml --max-time 300 ${debug}"
        eval "curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml ${resources}/open-distro/elasticsearch/roles/roles_mapping.yml --max-time 300 ${debug}"
        eval "curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml ${resources}/open-distro/elasticsearch/roles/internal_users.yml --max-time 300 ${debug}"        
        eval "rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f ${debug}"

        ## Create certificates
        eval "mkdir /etc/elasticsearch/certs ${debug}"
        eval "curl -so ~/wazuh-cert-tool.sh ${resources}/open-distro/tools/certificate-utility/wazuh-cert-tool.sh --max-time 300 ${debug}"
        eval "curl -so ~/instances.yml ${resources}/open-distro/tools/certificate-utility/instances.yml"
        eval "grep -A 4 'Elasticsearch nodes' ~/instances.yml | sed  's/<node-name>/elasticsearch/; s/node-IP/127.0.0.1/' >> ~/instances_tmp.yml"
        eval "grep -A 4 'Wazuh server nodes' ~/instances.yml | sed  's/<node-name>/filebeat/; s/node-IP/127.0.0.1/' >> ~/instances_tmp.yml"
        eval "grep -A 4 'Kibana node' ~/instances.yml | sed  's/<node-name>/kibana/; s/node-IP/127.0.0.1/' >> ~/instances_tmp.yml"
        eval "mv -f ~/instances_tmp.yml ~/instances.yml"

        export JAVA_HOME=/usr/share/elasticsearch/jdk/
        bash ~/wazuh-cert-tool.sh

        if [  "$?" != 0  ]; then
            logger -e "Certificates were not created"
            rollBack
            exit 1;
        else
            logger "Certificates created"
        fi     
        eval "cp ~/certs/elasticsearch* /etc/elasticsearch/certs/ ${debug}"
        eval "cp ~/certs/root-ca.pem /etc/elasticsearch/certs/ ${debug}"
        eval "cp ~/certs/admin* /etc/elasticsearch/certs/ ${debug}"
        
        # Configure JVM options for Elasticsearch
        ram_gb=$(free -g | awk '/^Mem:/{print $2}')
        ram=$(( ${ram_gb} / 2 ))

        if [ ${ram} -eq "0" ]; then
            ram=1;
        fi    
        eval "sed -i "s/-Xms1g/-Xms${ram}g/" /etc/elasticsearch/jvm.options ${debug}"
        eval "sed -i "s/-Xmx1g/-Xmx${ram}g/" /etc/elasticsearch/jvm.options ${debug}"

        applyLog4j2Mitigation

        eval "/usr/share/elasticsearch/bin/elasticsearch-plugin remove opendistro-performance-analyzer ${debug}"
        # Start Elasticsearch
        startService "elasticsearch"
        logger "Initializing Elasticsearch..."
        until $(curl -XGET https://localhost:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null); do
            echo -ne ${char}
            sleep 10
        done    
        echo ""

        eval "/usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -icl -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin-key.pem ${debug}"
        logger "Done"
        
    fi

}

## Filebeat
installFilebeat() {
    
    logger "Installing Filebeat..."
    
    if [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install filebeat=${ELK_VER} ${debug}"
    else
        eval "${sys_type} install filebeat${sep}${ELK_VER} -y -q  ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Filebeat installation failed"
        rollBack
        exit 1;
    else
        filebeatinstalled="1"
        eval "curl -so /etc/filebeat/filebeat.yml ${resources}/open-distro/filebeat/7.x/filebeat_unattended.yml --max-time 300  ${debug}"
        eval "curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.2/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 ${debug}"
        eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
        eval "curl -s '${repobaseurl}'/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"
        eval "mkdir /etc/filebeat/certs ${debug}"
        eval "cp ~/certs/root-ca.pem /etc/filebeat/certs/ ${debug}"
        eval "cp ~/certs/filebeat* /etc/filebeat/certs/ ${debug}"

        # Start Filebeat
        startService "filebeat"

        logger "Done"
    fi

}

## Kibana
installKibana() {
    
    logger "Installing Open Distro for Kibana..."
    if [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install opendistroforelasticsearch-kibana=${OD_VER} ${debug}"
    else
        eval "${sys_type} install opendistroforelasticsearch-kibana${sep}${OD_VER} -y ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Kibana installation failed"
        rollBack
        exit 1;
    else    
        kibanainstalled="1"
        eval "curl -so /etc/kibana/kibana.yml ${resources}/open-distro/kibana/7.x/kibana_unattended.yml --max-time 300 ${debug}"
        eval "mkdir /usr/share/kibana/data ${debug}"
        eval "chown -R kibana:kibana /usr/share/kibana/ ${debug}"
        eval "sudo -u kibana /usr/share/kibana/bin/kibana-plugin install '${repobaseurl}'/ui/kibana/wazuh_kibana-${WAZUH_VER}_${ELK_VER}-${WAZUH_KIB_PLUG_REV}.zip ${debug}"
        if [  "$?" != 0  ]; then
            logger -e "Wazuh Kibana plugin could not be installed."
            rollBack

            exit 1;
        fi     
        eval "mkdir /etc/kibana/certs ${debug}"
        eval "cp ~/certs/kibana* /etc/kibana/certs/ ${debug}"
        eval "cp ~/certs/root-ca.pem /etc/kibana/certs/ ${debug}"
        eval "chown -R kibana:kibana /etc/kibana/ ${debug}"
        eval "chmod -R 500 /etc/kibana/certs ${debug}"
        eval "chmod 440 /etc/kibana/certs/kibana* ${debug}"
        eval "setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node ${debug}"

        # Start Kibana
        startService "kibana"

        logger "Done"
    fi

}

checkFlavor() {
    if [ -n "$elasticinstalled" ]; then
        flavor=$(grep 'opendistro' /etc/elasticsearch/elasticsearch.yml)
    fi

    if [ -n "$flavor" ]; then
        logger "OD"
    fi
}

checkInstalled() {
    
    if [ "${sys_type}" == "yum" ]; then
        wazuhinstalled=$(yum list installed 2>/dev/null | grep wazuh-manager)
    elif [ "${sys_type}" == "zypper" ]; then
        wazuhinstalled=$(zypper packages --installed-only | grep wazuh-manager | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        wazuhinstalled=$(apt list --installed  2>/dev/null | grep wazuh-manager)
    fi    

    if [ -n "${wazuhinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            wazuhversion=$(echo ${wazuhinstalled} | awk '{print $11}')
        else
            wazuhversion=$(echo ${wazuhinstalled} | awk '{print $2}')
        fi    
    fi

    if [ "${sys_type}" == "yum" ]; then
        elasticinstalled=$(yum list installed 2>/dev/null | grep opendistroforelasticsearch)
    elif [ "${sys_type}" == "zypper" ]; then
        elasticinstalled=$(zypper packages --installed-only | grep opendistroforelasticsearch | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        elasticinstalled=$(apt list --installed  2>/dev/null | grep opendistroforelasticsearch)
    fi 

    if [ -n "${elasticinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            odversion=$(echo ${elasticinstalled} | awk '{print $11}')
        else
            odversion=$(echo ${elasticinstalled} | awk '{print $2}')
        fi  
    fi

    if [ "${sys_type}" == "yum" ]; then
        filebeatinstalled=$(yum list installed 2>/dev/null | grep filebeat)
    elif [ "${sys_type}" == "zypper" ]; then
        filebeatinstalled=$(zypper packages --installed-only | grep filebeat | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        filebeatinstalled=$(apt list --installed  2>/dev/null | grep filebeat)
    fi 

    if [ -n "${filebeatinstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            filebeatversion=$(echo ${filebeatinstalled} | awk '{print $11}')
        else
            filebeatversion=$(echo ${filebeatinstalled} | awk '{print $2}')
        fi  
    fi    

    if [ "${sys_type}" == "yum" ]; then
        kibanainstalled=$(yum list installed 2>/dev/null | grep opendistroforelasticsearch-kibana)
    elif [ "${sys_type}" == "zypper" ]; then
        kibanainstalled=$(zypper packages --installed-only | grep opendistroforelasticsearch-kibana | grep i+)
    elif [ "${sys_type}" == "apt-get" ]; then
        kibanainstalled=$(apt list --installed  2>/dev/null | grep opendistroforelasticsearch-kibana)
    fi 

    if [ -n "${kibanainstalled}" ]; then
        if [ ${sys_type} == "zypper" ]; then
            kibanaversion=$(echo ${kibanainstalled} | awk '{print $11}')
        else
            kibanaversion=$(echo ${kibanainstalled} | awk '{print $2}')
        fi  
    fi  

    if [ -z "${wazuhinstalled}" ] && [ -z "${elasticinstalled}" ] && [ -z "${filebeatinstalled}" ] && [ -z "${kibanainstalled}" ] && [ -n "${uninstall}" ]; then 
        logger -e "No Wazuh components were found on the system."
        exit 1;        
    fi

    if [ -n "${wazuhinstalled}" ] || [ -n "${elasticinstalled}" ] || [ -n "${filebeatinstalled}" ] || [ -n "${kibanainstalled}" ]; then 
        if [ -n "${ow}" ]; then
             overwrite
        
        elif [ -n "${uninstall}" ]; then
            logger -w "Removing the installed items"
            rollBack
        else
            logger -e "All the Wazuh componets were found on this host. If you want to overwrite the current installation, run this script back using the option -o/--overwrite. NOTE: This will erase all the existing configuration and data."
            exit 1;
        fi
    fi          

}

overwrite() {  
    rollBack
    addWazuhrepo
    installPrerequisites
    if [ -n "${wazuhinstalled}" ]; then
        installWazuh
    fi
    if [ -n "${elasticinstalled}" ]; then
        installElasticsearch
    fi    
    if [ -n "${filebeatinstalled}" ]; then
        installFilebeat
    fi
    if [ -n "${kibanainstalled}" ]; then
        installKibana
    fi    
    checkInstallation     
}

networkCheck() {
    connection=$(curl -I https://packages.wazuh.com/ -s | grep 200 | awk '{print $2}')
    if [ ${connection} != "200" ]; then
        logger -e "No internet connection. To perform an offline installation, please run this script with the option -d/--download-packages in a computer with internet access, copy the wazuh-packages.tar file generated on this computer and run again this script."
        exit 1;
    fi
}

specsCheck() {

    cores=$(cat /proc/cpuinfo | grep processor | wc -l)
    ram_gb=$(free -m | awk '/^Mem:/{print $2}')
    
}

## Health check
healthCheck() {

    specsCheck
    if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]; then
        logger -e "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
        exit 1;
    else
        logger "Starting the installation..."
    fi

}

changePasswords() {
    eval "curl -so ~/wazuh-passwords-tool.sh ${resources}/open-distro/tools/wazuh-passwords-tool.sh --max-time 300 ${debug}"
    if [ -n "${verbose}" ]; then
        bash ~/wazuh-passwords-tool.sh -a -v
    else
        VERBOSE='> /dev/null 2>&1'
        bash ~/wazuh-passwords-tool.sh -a
    fi    
    
    if [  "$?" != 0  ]; then
        logger -e "The passwords could not be changed"
        rollBack
        exit 1; 
    fi
}

checkInstallation() {

    changePasswords
    wazuhpass=$(grep "password:" /etc/filebeat/filebeat.yml )
    ra="  password: "
    wazuhpass="${wazuhpass//$ra}"
    logger "Checking the installation..."
    eval "curl -XGET https://localhost:9200 -uwazuh:${wazuhpass} -k --max-time 300 ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "Elasticsearch was not successfully installed."
        rollBack
        exit 1;     
    else
        logger "Elasticsearch installation succeeded."
    fi
    eval "filebeat test output ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "Filebeat was not successfully installed."
        rollBack
        exit 1;     
    else
        logger "Filebeat installation succeeded."
    fi    
    logger "Initializing Kibana (this may take a while)"
    until [[ "$(curl -XGET https://localhost/status -I -uwazuh:${wazuhpass} -k -s --max-time 300 | grep "200 OK")" ]]; do
        echo -ne $char
        sleep 10
    done
    echo ""
    setWazuhUserRBACPermissions
    logger $'\nInstallation finished'
    logger $'\nYou can access the web interface https://<kibana_ip>. The credentials are wazuh:'${wazuhpass}''

    exit 0;

}

setWazuhUserRBACPermissions() {
    TOKEN=$(curl -u wazuh:wazuh -s -k -X GET "https://localhost:55000/security/user/authenticate?raw=true")
    eval "curl -s -k -X POST \"https://localhost:55000/security/rules?pretty=true\" -H \"Authorization: Bearer $TOKEN\" -H \"Content-Type: application/json\" -d '{\"name\": \"wazuh_rbac\",\"rule\": {\"FIND\": {\"user_name\": \"wazuh\"}}}' ${debug}"
    eval "curl -s -k -X POST \"https://localhost:55000/security/roles/1/rules?rule_ids=100&pretty=true\" -H \"Authorization: Bearer $TOKEN\" ${debug}"
}

main() {

    if [ "$EUID" -ne 0 ]; then
        logger -e "This script must be run as root."
        exit 1;
    fi   

    checkArch
    touch /var/log/wazuh-unattended-installation.log

    if [ -n "$1" ]; then      
        while [ -n "$1" ]
        do
            case "$1" in 
            "-i"|"--ignore-healthcheck") 
                ignore=1          
                shift 1
                ;; 
            "-v"|"--verbose") 
                verbose=1          
                shift 1
                ;; 
            "-o"|"--overwrite")  
                ow=1 
                shift 1     
                ;;  
            "-r"|"--uninstall")  
                uninstall=1 
                shift 1     
                ;;                                                              
            "-h"|"--help")        
                getHelp
                ;;                                         
            *)
                getHelp
            esac
        done    

        if [ -n "${verbose}" ]; then
            debug='2>&1 | tee -a /var/log/wazuh-unattended-installation.log'
        fi

        if [ -n "${uninstall}" ]; then
            checkInstalled
            exit 0;
        fi        
        
        if [ -n "${ignore}" ]; then
            logger -w "Health-check ignored."    
            checkInstalled
        else
            checkInstalled
            healthCheck           
        fi            
        installPrerequisites
        addWazuhrepo
        installWazuh
        installElasticsearch
        installFilebeat
        installKibana
        checkInstallation    
    else
        checkInstalled  
        healthCheck   
        installPrerequisites
        addWazuhrepo
        installWazuh
        installElasticsearch
        installFilebeat
        installKibana
        checkInstallation  
    fi

}

main "$@"
