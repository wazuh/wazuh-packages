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
            echo "All the Wazuh componets were found on this host. If you want to overwrite the current installation, run this script back using the option -o/--overwrite. NOTE: This will erase all the existing configuration and data."
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


    logger "Creating the certificates..."
    eval "curl -so ~/search-guard-tlstool-1.8.zip https://maven.search-guard.com/search-guard-tlstool/1.8/search-guard-tlstool-1.8.zip --max-time 300 ${debug}"
    eval "unzip ~/search-guard-tlstool-1.8.zip -d ~/searchguard ${debug}"
    eval "curl -so ~/searchguard/search-guard.yml https://packages.wazuh.com/resources/${WAZUH_MAJOR}/open-distro/unattended-installation/distributed/templates/search-guard-unattended.yml --max-time 300 ${debug}"

    if [ -n "${single}" ]; then
        echo -e "\n" >> ~/searchguard/search-guard.yml
        echo "nodes:" >> ~/searchguard/search-guard.yml
        echo '  - name: "'${iname}'"' >> ~/searchguard/search-guard.yml
        echo '    dn: CN="'${iname}'",OU=Docu,O=Wazuh,L=California,C=US' >> ~/searchguard/search-guard.yml
        echo '    ip:' >> ~/searchguard/search-guard.yml
        echo '      - "'${nip}'"' >> ~/searchguard/search-guard.yml
    else
        echo -e "\n" >> ~/searchguard/search-guard.yml
        echo "nodes:" >> ~/searchguard/search-guard.yml
        for i in "${!IMN[@]}"; do
            echo '  - name: "'${IMN[i]}'"' >> ~/searchguard/search-guard.yml
            echo '    dn: CN="'${IMN[i]}'",OU=Docu,O=Wazuh,L=California,C=US' >> ~/searchguard/search-guard.yml
            echo '    ip:' >> ~/searchguard/search-guard.yml
            echo '      - "'${DSH[i]}'"' >> ~/searchguard/search-guard.yml
        done      
    fi
    kip=$(grep -A 1 "Kibana-instance" ~/config.yml | tail -1)
    rm="- "
    kip="${kip//$rm}"        
    echo '  - name: "kibana"' >> ~/searchguard/search-guard.yml
    echo '    dn: CN="kibana",OU=Docu,O=Wazuh,L=California,C=US' >> ~/searchguard/search-guard.yml
    echo '    ip:' >> ~/searchguard/search-guard.yml
    echo '      - "'${kip}'"' >> ~/searchguard/search-guard.yml      
    awk -v RS='' '/# Clients certificates/' ~/config.yml >> ~/searchguard/search-guard.yml
    eval "chmod +x ~/searchguard/tools/sgtlstool.sh ${debug}"
    eval "bash ~/searchguard/tools/sgtlstool.sh -c ~/searchguard/search-guard.yml -ca -crt -t /etc/elasticsearch/certs/ ${debug}"
    if [  "$?" != 0  ]; then
        echo "Error: certificates were not created"
        exit 1;
    else
        logger "Certificates created"
    fi
    #awk -v RS='' '/## Certificates/' ~/config.yml >> /etc/elasticsearch/certs/searchguard/search-guard.yml
}

copyCertificates() {

    if [ -n "${single}" ]; then
        eval "mv /etc/elasticsearch/certs/${iname}.pem /etc/elasticsearch/certs/elasticsearch.pem ${debug}"
        eval "mv /etc/elasticsearch/certs/${iname}.key /etc/elasticsearch/certs/elasticsearch.key ${debug}"
        eval "mv /etc/elasticsearch/certs/${iname}_http.pem /etc/elasticsearch/certs/elasticsearch_http.pem ${debug}"
        eval "mv /etc/elasticsearch/certs/${iname}_http.key /etc/elasticsearch/certs/elasticsearch_http.key ${debug}"
        eval "rm /etc/elasticsearch/certs/client-certificates.readme /etc/elasticsearch/certs/elasticsearch_elasticsearch_config_snippet.yml search-guard-tlstool-1.8.zip -f ${debug}"
    else
        if [ -z "${certificates}" ]; then
            eval "mv ~/certs.tar /etc/elasticsearch/certs ${debug}"
            eval "tar -xf certs.tar ${IMN[pos]}.pem ${IMN[pos]}.key ${IMN[pos]}_http.pem ${IMN[pos]}_http.key root-ca.pem ${debug}"
        fi
        eval "mv /etc/elasticsearch/certs/${IMN[pos]}.pem /etc/elasticsearch/certs/elasticsearch.pem ${debug}"
        eval "mv /etc/elasticsearch/certs/${IMN[pos]}.key /etc/elasticsearch/certs/elasticsearch.key ${debug}"
        eval "mv /etc/elasticsearch/certs/${IMN[pos]}_http.pem /etc/elasticsearch/certs/elasticsearch_http.pem ${debug}"
        eval "mv /etc/elasticsearch/certs/${IMN[pos]}_http.key /etc/elasticsearch/certs/elasticsearch_http.key ${debug}"
        eval "rm /etc/elasticsearch/certs/client-certificates.readme /etc/elasticsearch/certs/elasticsearch_elasticsearch_config_snippet.yml ~/search-guard-tlstool-1.8.zip -f ${debug}"
    fi
    eval "/usr/share/elasticsearch/bin/elasticsearch-plugin remove opendistro-performance-analyzer ${debug}"
    if [[ -n "${certificates}" ]] || [[ -n "${single}" ]]; then
        cp ~/config.yml /etc/elasticsearch/certs/
        tar -cf /etc/elasticsearch/certs/certs.tar *
        mv /etc/elasticsearch/certs/certs.tar ~/certs.tar
    fi

}

