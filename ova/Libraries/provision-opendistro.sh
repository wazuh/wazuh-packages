#!/bin/bash
char="#"
debug=''
sys_type="yum"

logger() {

    echo $1
}

startService() {

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        systemctl daemon-reload 
        systemctl enable $1.service 
        systemctl start $1.service 
        if [ "$?" != 0 ]
        then
            echo "${1^} could not be started."
            systemctl status elasticsearch -l
            exit 1;
        else
            echo "${1^} started"
        fi
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        chkconfig $1 on 
        service $1 start 
        /etc/init.d/$1 start 
        if [ "$?" != 0 ]
        then
            echo "${1^} could not be started."
            exit 1;
        else
            echo "${1^} started"
        fi
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        /etc/rc.d/init.d/$1 start 
        if [ "$?" != 0 ]
        then
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

## Show script usage
getHelp() {

   echo ""
   echo "Usage: $0 arguments"
   echo -e "\t-d   | --debug Shows the complete installation output"
   echo -e "\t-i   | --ignore-health-check Ignores the health-check"
   echo -e "\t-h   | --help Shows help"
   exit $1 # Exit script after printing help
}


## Install the required packages for the installation
installPrerequisites() {
    logger "Installing all necessary utilities for the installation..."
    $sys_type install curl unzip wget libcap -y -q 
    echo -e '[AdoptOpenJDK] \nname=AdoptOpenJDK \nbaseurl=http://adoptopenjdk.jfrog.io/adoptopenjdk/rpm/centos/$releasever/$basearch\nenabled=1\ngpgcheck=1\ngpgkey=https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public' | tee /etc/yum.repos.d/adoptopenjdk.repo $debug
    $sys_type install adoptopenjdk-11-hotspot -y -q 
    export JAVA_HOME=/usr/

    if [ "$?" != 0 ]; then
        echo "Error: Prerequisites could not be installed"
        exit 1;
    else
        logger "Done"
    fi
}

## Add the Wazuh repository
addWazuhrepo() {
    major_version="$(echo ${WAZUH_VERSION} | head -c 1)"
    logger "Adding the Wazuh repository..."
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH 
    if [ "${STATUS_PACKAGES}" = "prod" ]; then
      logger "Adding production repository..."
      echo -e "[wazuh_repo]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/${major_version}.x/yum/\nprotect=1" | tee /etc/yum.repos.d/wazuh.repo $debug
    elif [ "${STATUS_PACKAGES}" = "dev" ]; then
      logger "Adding development repository..."
      echo -e '[wazuh_pre-release]\ngpgcheck=1\ngpgkey=https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-dev.wazuh.com/pre-release/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo $debug
    fi

    if [ "$?" != 0 ]; then
        echo "Error: Wazuh repository could not be added"
        exit 1;
    else
        logger "Done"
    fi
}

## Wazuh manager
installWazuh() {
 # If version is less than 4.0.0 install wazuh api

    logger "Installing the Wazuh manager..."
    $sys_type install wazuh-manager-${WAZUH_VERSION} -y -q 
    if [ "$?" != 0 ]; then
        echo "Error: Wazuh installation failed"
        exit 1;
    else
        logger "Done"
    fi
}

## Elasticsearch
installElasticsearch() {

    logger "Installing Open Distro for Elasticsearch..."
    $sys_type install opendistroforelasticsearch-${OPENDISTRO_VERSION} -y -q 

    if [ "$?" != 0 ]; then
        echo "Error: Elasticsearch installation failed"
        exit 1;
    else
        logger "Done"

        logger "Configuring Elasticsearch..."


        curl -so /etc/elasticsearch/elasticsearch.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCH}/resources/open-distro/elasticsearch/7.x/elasticsearch_all_in_one.yml --max-time 300
        
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCH}/resources/open-distro/elasticsearch/roles/roles.yml --max-time 300
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCH}/resources/open-distro/elasticsearch/roles/roles_mapping.yml --max-time 300
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCH}/resources/open-distro/elasticsearch/roles/internal_users.yml --max-time 300
        rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f
        mkdir -p /etc/elasticsearch/certs $debug
        cd /etc/elasticsearch/certs 
        curl -so /etc/elasticsearch/certs/search-guard-tlstool-1.8.zip https://maven.search-guard.com/search-guard-tlstool/1.8/search-guard-tlstool-1.8.zip --max-time 300 
        unzip search-guard-tlstool-1.8.zip -d searchguard 
        curl -so /etc/elasticsearch/certs/searchguard/search-guard.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCH}/resources/open-distro/searchguard/search-guard-aio.yml --max-time 300 
        chmod +x searchguard/tools/sgtlstool.sh 
        ./searchguard/tools/sgtlstool.sh -c ./searchguard/search-guard.yml -ca -crt -t /etc/elasticsearch/certs/ $debug 
        if [ "$?" != 0 ]; then
            echo "Error: certificates were not created"
            exit 1
        else
            logger "Certificates created"
        fi
        rm /etc/elasticsearch/certs/client-certificates.readme /etc/elasticsearch/certs/elasticsearch_elasticsearch_config_snippet.yml search-guard-tlstool-1.7.zip -f $debug

        # Configure JVM options for Elasticsearch
        
        ram_gb=$(free -g | awk '/^Mem:/{print $2}')
        ram=$(( ${ram_gb} / 2 ))

        if [ ${ram} -eq "0" ]; then
            ram=1;
        fi
        sed -i "s/-Xms1g/-Xms${ram}g/" "/etc/elasticsearch/jvm.options" $debug
        sed -i "s/-Xmx1g/-Xmx${ram}g/" "/etc/elasticsearch/jvm.options" $debug
        
        jv=$(java -version 2>&1 | grep -o -m1 '1.8.0' )
        if [ "$jv" = "1.8.0" ]; then
            ln -s /usr/lib/jvm/java-1.8.0/lib/tools.jar /usr/share/elasticsearch/lib/
            echo "root hard nproc 4096" >> /etc/security/limits.conf
            echo "root soft nproc 4096" >> /etc/security/limits.conf
            echo "elasticsearch hard nproc 4096" >> /etc/security/limits.conf
            echo "elasticsearch soft nproc 4096" >> /etc/security/limits.conf
            echo "bootstrap.system_call_filter: false" >> /etc/elasticsearch/elasticsearch.yml
        fi
        
        # Start Elasticsearch
        startService "elasticsearch"
        echo "Initializing Elasticsearch..."
        until $(curl -XGET https://localhost:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null); do
            echo -ne $char
            sleep 10
        done

        cd /usr/share/elasticsearch/plugins/opendistro_security/tools/ $debug
        ./securityadmin.sh -cd ../securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin.key $debug

        echo "Done"
    fi
}

## Filebeat
installFilebeat() {
    logger "Installing Filebeat..."

    $sys_type install filebeat-"${ELK_VERSION}" -y -q  $debug
    if [ "$?" != 0 ]; then
        echo "Error: Filebeat installation failed"
        exit 1;
    else
        major_version="$(echo ${WAZUH_VERSION} | head -c 1)"



        curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCH}/resources/open-distro/filebeat/7.x/filebeat_all_in_one.yml --max-time 300  $debug
        curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCH}/resources/open-distro/filebeat/7.x/wazuh-template.json --max-time 300 $debug
        chmod go+r /etc/filebeat/wazuh-template.json $debug
        
        curl -s https://packages.wazuh.com/${major_version}.x/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module $debug
        mkdir -p /etc/filebeat/certs $debug
        cp /etc/elasticsearch/certs/root-ca.pem /etc/filebeat/certs/ $debug
        mv /etc/elasticsearch/certs/filebeat* /etc/filebeat/certs/ $debug
        # Start Filebeat
        startService "filebeat"
        logger "Done"
    fi
}

## Kibana
installKibana() {
    major_version="$(echo ${WAZUH_VERSION} | head -c 1)"
    logger "Installing Open Distro for Kibana..."
    $sys_type install opendistroforelasticsearch-kibana-${OPENDISTRO_VERSION} -y -q $debug
    if [ "$?" != 0 ]; then
        echo "Error: Kibana installation failed"
        exit 1;
    else
        curl -so /etc/kibana/kibana.yml https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCH}/resources/open-distro/kibana/7.x/kibana_all_in_one.yml --max-time 300 $debug
        cd /usr/share/kibana $debug

        if [ "${STATUS_PACKAGES}" = "prod" ]; then
            sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/${major_version}.x/ui/kibana/wazuhapp-${WAZUH_VERSION}_${ELK_VERSION}.zip $debug
        elif [ "${STATUS_PACKAGES}" = "dev" ]; then
            sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages-dev.wazuh.com/pre-release/ui/kibana/wazuhapp-${WAZUH_VERSION}_${ELK_VERSION}.zip $debug
        fi

        if [ "${STATUS_PACKAGES}" = "prod" ]; then
            sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/${major_version}.x/ui/kibana/wazuh_kibana-${WAZUH_VERSION}_${ELK_VERSION}-1.zip $debug
        elif [ "${STATUS_PACKAGES}" = "dev" ]; then
            sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages-dev.wazuh.com/pre-release/ui/kibana/wazuh_kibana-${WAZUH_VERSION}_${ELK_VERSION}-1.zip $debug
        fi        
        
        if [ "$?" != 0 ]
        then
            echo "Error: Wazuh Kibana plugin could not be installed."
            exit 1;
        fi
        mkdir -p /etc/kibana/certs $debug
        mv /etc/elasticsearch/certs/kibana* /etc/kibana/certs/ $debug
        setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node $debug

        # Start Kibana
        startService "kibana"

        logger "Done"
    fi
}

## Health check
healthCheck() {

    cores=$(nproc)
    ram_gb=$(free -m | awk '/^Mem:/{print $2}')

    if [[ $cores -lt 2 ]] || [[ $ram_gb -lt 4096 ]]; then
        echo "The system must have at least 4Gb of RAM and 2 CPUs"
        exit 1;
    else
        echo "Starting the installation..."
    fi
}

checkInstallation() {

    logger "Checking the installation..."
    curl -XGET https://localhost:9200 -uadmin:admin -k --max-time 300 $debug
    if [ "$?" != 0 ]; then
        echo "Error: Elasticsearch was not successfully installed."
        exit 1
    else
        echo "Elasticsearch installation succeeded."
    fi
    filebeat test output $debug
    if [ "$?" != 0 ]; then
        echo "Error: Filebeat was not successfully installed."
        exit 1;
    else
        echo "Filebeat installation succeeded."
    fi
    logger "Initializing Kibana (this may take a while)"
    until [[ "$(curl -XGET https://localhost/status -I -uadmin:admin -k -s | grep "200 OK")" ]]; do
        echo -ne $char
        sleep 10
    done
    echo $'\nInstallation finished'
    exit 0;
}

cleanInstall(){

    rm -rf /etc/yum.repos.d/adoptopenjdk.repo
    rm -rf /etc/yum.repos.d/opendistroforelasticsearch-artifacts.repo
    rm -rf  /etc/yum.repos.d/wazuh.repo
    yum clean all
}
