repogpg="https://packages.wazuh.com/key/GPG-KEY-WAZUH"
repobaseurl="https://packages.wazuh.com/4.x"

getConfig() {
    if [ -n "${local}" ]; then
        cp ./$config_path/$1 $2
    else
        curl -so $2 $resources_config/$1
    fi
}

checkSystem() {
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
}

checkArch() {
    arch=$(uname -m)

    if [ ${arch} != "x86_64" ]; then
        echo "Uncompatible system. This script must be run on a 64-bit system."
        exit 1;
    fi
}

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
        echo "Error: Prerequisites could not be installed"
        exit 1;
    else
        logger "Done"
    fi          
}

addWazuhrepo() {
    logger "Adding the Wazuh repository..."

    if [ ${sys_type} == "yum" ]; then
        eval "rpm --import ${repogpg} ${debug}"
        eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo ${debug}"
    elif [ ${sys_type} == "zypper" ]; then
        eval "rpm --import ${repogpg} ${debug}"
        eval "echo -e '[wazuh]\ngpgcheck=1\ngpgkey=${repogpg}\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl='${repobaseurl}'/yum/\nprotect=1' | tee /etc/zypp/repos.d/wazuh.repo ${debug}"            
    elif [ ${sys_type} == "apt-get" ]; then
        eval "curl -s ${repogpg} --max-time 300 | apt-key add - ${debug}"
        eval "echo "deb '${repobaseurl}'/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list ${debug}"
        eval "apt-get update -q ${debug}"
    fi    

    logger "Done" 
}

checkFlavor() {
    if [ -n "$elasticinstalled" ]; then
        flavor=$(grep 'opendistro' /etc/elasticsearch/elasticsearch.yml)
    fi

    if [ -n "$flavor" ]; then
        echo "OD"
    fi
}

checkInstalled() {
    
    if [ "${sys_type}" == "yum" ]; then
        wazuhinstalled=$(yum list installed 2>/dev/null | grep wazuh-manager)
    elif [ "${sys_type}" == "zypper" ]; then
        wazuhinstalled=$(zypper packages --installed | grep wazuh-manager | grep i+)
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
        elasticinstalled=$(zypper packages --installed | grep opendistroforelasticsearch | grep i+ | grep noarch)
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
        filebeatinstalled=$(zypper packages --installed | grep filebeat | grep i+ | grep noarch)
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
        kibanainstalled=$(zypper packages --installed | grep opendistroforelasticsearch-kibana | grep i+)
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

    if [ -z "${wazuhinstalled}" ] || [ -z "${elasticinstalled}" ] || [ -z "${filebeatinstalled}" ] || [ -z "${kibanainstalled}" ] && [ -n "${uninstall}" ]; then 
        echo "Error: No Wazuh components were found on the system."
        exit 1;        
    fi

    if [ -n "${wazuhinstalled}" ] || [ -n "${elasticinstalled}" ] || [ -n "${filebeatinstalled}" ] || [ -n "${kibanainstalled}" ]; then 
        if [ -n "${ow}" ]; then
            overwrite
        
        elif [ -n "${uninstall}" ]; then
            echo "Removing the installed items"
            rollBack
        else
            echo "All the Wazuh components were found on this host. If you want to overwrite the current installation, run this script back using the option -o/--overwrite. NOTE: This will erase all the existing configuration and data."
            exit 1;
        fi
    fi          

}

startService() {

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        eval "systemctl daemon-reload ${debug}"
        eval "systemctl enable $1.service ${debug}"
        eval "systemctl start $1.service ${debug}"
        if [  "$?" != 0  ]; then
            echo "${1^} could not be started."
            rollBack
            exit 1;
        else
            echo "${1^} started"
        fi  
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        eval "chkconfig $1 on ${debug}"
        eval "service $1 start ${debug}"
        eval "/etc/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            echo "${1^} could not be started."
            rollBack
            exit 1;
        else
            echo "${1^} started"
        fi     
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        eval "/etc/rc.d/init.d/$1 start ${debug}"
        if [  "$?" != 0  ]; then
            echo "${1^} could not be started."
            rollBack
            exit 1;
        else
            echo "${1^} started"
        fi             
    else
        echo "Error: ${1^} could not start. No service manager found on the system."
        exit 1;
    fi

}

createCertificates() {

    if [ -n "${AIO}" ]; then
        eval "getConfig certificate/instances_aio.yml ./instances.yml ${debug}"
    fi

    readInstances
    generateRootCAcertificate
    generateAdmincertificate
    generateElasticsearchcertificates
    generateFilebeatcertificates
    generateKibanacertificates
    cleanFiles
}

checkNodes() {

    head=$(head -n1 ./config.yml)
    if [ "${head}" == "## Multi-node configuration" ]
    then
        master=1
    else
        single=1
    fi

}

specsCheck() {

    cores=$(cat /proc/cpuinfo | grep processor | wc -l)
    ram_gb=$(free -m | awk '/^Mem:/{print $2}')
    
}

healthCheck() {
    specsCheck
    case "$1" in
        "elasticsearch")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]; then
                echo "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1;
            else
                echo "Starting the installation..."
            fi
            ;;

        "kibana")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]; then
                echo "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1;
            else
                echo "Starting the installation..."
            fi
            ;;
        "wazuh")
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]
            then
                echo "Your system does not meet the recommended minimum hardware requirements of 2Gb of RAM and 2 CPU cores . If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1;
            else
                echo "Starting the installation..."
            fi
            ;;
        "AIO")
            specsCheck
            if [ ${cores} -lt 2 ] || [ ${ram_gb} -lt 3700 ]; then
                echo "Your system does not meet the recommended minimum hardware requirements of 4Gb of RAM and 2 CPU cores. If you want to proceed with the installation use the -i option to ignore these requirements."
                exit 1;
            else
                echo "Starting the installation..."
            fi
            ;;
    esac
}

rollBack() {

    if [ -z "${uninstall}" ]; then
        echo "Cleaning the installation" 
    fi   
    
    if [ -n "${wazuhinstalled}" ]; then
        echo "Removing the Wazuh manager..."
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
        echo "Removing Elasticsearch..."
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
        eval "rm -rf ./search-guard-tlstool-1.8.zip ${debug}"
        eval "rm -rf ./searchguard ${debug}"
    fi

    if [ -n "${filebeatinstalled}" ]; then
        echo "Removing Filebeat..."
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
        echo "Removing Kibana..."
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
        echo "Installation cleaned. Check the /var/log/wazuh-unattended-installation.log file to learn more about the issue."
    fi

}
