#!/bin/bash
char="#"
sys_type="yum"
searchguard_version="1.8"
resources_url=https://raw.githubusercontent.com/wazuh/wazuh-documentation/${BRANCH}

logger() {

    echo $1
}

startService() {

    if [ -n "$(ps -e | egrep ^\ *1\ .*systemd$)" ]; then
        systemctl daemon-reload 
        systemctl enable $1.service 
        systemctl start $1.service 
        if [ "$?" != 0 ]; then
            logger "${1^} could not be started."
            exit 1;
        else
            logger "${1^} started"
        fi
    elif [ -n "$(ps -e | egrep ^\ *1\ .*init$)" ]; then
        chkconfig $1 on 
        service $1 start 
        /etc/init.d/$1 start 
        if [ "$?" != 0 ]; then
            logger "${1^} could not be started."
            exit 1;
        else
            logger "${1^} started"
        fi
    elif [ -x /etc/rc.d/init.d/$1 ] ; then
        /etc/rc.d/init.d/$1 start 
        if [ "$?" != 0 ]; then
            logger "${1^} could not be started."
            exit 1;
        else
            logger "${1^} started"
        fi
    else
        logger "Error: ${1^} could not start. No service manager found on the system."
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
    echo -e '[AdoptOpenJDK] \nname=AdoptOpenJDK \nbaseurl=http://adoptopenjdk.jfrog.io/adoptopenjdk/rpm/centos/$releasever/$basearch\nenabled=1\ngpgcheck=1\ngpgkey=https://adoptopenjdk.jfrog.io/adoptopenjdk/api/gpg/key/public' | tee /etc/yum.repos.d/adoptopenjdk.repo 
    $sys_type install adoptopenjdk-11-hotspot -y -q 
    export JAVA_HOME=/usr/

    if [ "$?" != 0 ]; then
        logger "Error: Prerequisites could not be installed"
        exit 1;
    else
        logger "Done"
    fi
}

## Add the Wazuh repository
addWazuhrepo() {
    WAZUH_MAJOR="$(echo ${WAZUH_VERSION} | head -c 1)"
    logger "Adding the Wazuh repository..."
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH 
    if [ "${STATUS_PACKAGES}" = "prod" ]; then
      logger "Adding production repository..."
      echo -e "[wazuh_repo]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/${WAZUH_MAJOR}.x/yum/\nprotect=1" | tee /etc/yum.repos.d/wazuh.repo 
    elif [ "${STATUS_PACKAGES}" = "dev" ]; then
      logger "Adding development repository..."
      echo -e '[wazuh_pre-release]\ngpgcheck=1\ngpgkey=https://packages-dev.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-dev.wazuh.com/pre-release/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo 
    fi

    if [ "$?" != 0 ]; then
        logger "Error: Wazuh repository could not be added"
        exit 1;
    else
        logger "Done"
    fi
}

## Wazuh manager
installWazuh() {

    logger "Installing the Wazuh manager..."
    $sys_type install wazuh-manager-${WAZUH_VERSION} -y -q 
    if [ "$?" != 0 ]; then
        logger "Error: Wazuh installation failed"
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
        logger "Error: Elasticsearch installation failed"
        exit 1;
    else
        logger "Done"

        logger "Configuring Elasticsearch..."


        curl -so /etc/elasticsearch/elasticsearch.yml ${resources_url}/resources/open-distro/elasticsearch/7.x/elasticsearch_all_in_one.yml --max-time 300
        
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml ${resources_url}/resources/open-distro/elasticsearch/roles/roles.yml --max-time 300
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml ${resources_url}/resources/open-distro/elasticsearch/roles/roles_mapping.yml --max-time 300
        curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml ${resources_url}/resources/open-distro/elasticsearch/roles/internal_users.yml --max-time 300
        rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f
        mkdir -p /etc/elasticsearch/certs 
        cd /etc/elasticsearch/certs 
        curl -so /etc/elasticsearch/certs/search-guard-tlstool-${searchguard_version}.zip https://maven.search-guard.com/search-guard-tlstool/${searchguard_version}/search-guard-tlstool-${searchguard_version}.zip --max-time 300 
        unzip search-guard-tlstool-${searchguard_version}.zip -d searchguard 
        curl -so /etc/elasticsearch/certs/searchguard/search-guard.yml ${resources_url}/resources/open-distro/searchguard/search-guard-aio.yml --max-time 300 
        chmod +x searchguard/tools/sgtlstool.sh 
        ./searchguard/tools/sgtlstool.sh -c ./searchguard/search-guard.yml -ca -crt -t /etc/elasticsearch/certs/  

        if [ "$?" != 0 ]; then
            logger "Error: certificates were not created"
            exit 1
        else
            logger "Certificates created"
        fi
        rm /etc/elasticsearch/certs/client-certificates.readme /etc/elasticsearch/certs/elasticsearch_elasticsearch_config_snippet.yml search-guard-tlstool-1.7.zip -f 


        # # Configure JVM options for Elasticsearch
        jv=$(java -version 2>&1 | grep -o -m1 '1.8.0') || : 
        if [ "${jv}" = "1.8.0" ]; then
            ln -s /usr/lib/jvm/java-1.8.0/lib/tools.jar /usr/share/elasticsearch/lib/
            echo "root hard nproc 4096" >> /etc/security/limits.conf
            echo "root soft nproc 4096" >> /etc/security/limits.conf
            echo "elasticsearch hard nproc 4096" >> /etc/security/limits.conf
            echo "elasticsearch soft nproc 4096" >> /etc/security/limits.conf
            echo "bootstrap.system_call_filter: false" >> /etc/elasticsearch/elasticsearch.yml
        fi
        # Start Elasticsearch
        startService "elasticsearch"
        logger "Initializing Elasticsearch..."
        until $(curl -XGET https://localhost:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null); do
            logger -ne $char
            sleep 10
        done

        cd /usr/share/elasticsearch/plugins/opendistro_security/tools/ 
        ./securityadmin.sh -cd ../securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin.key 

        logger "Done"
    fi
}

## Filebeat
installFilebeat() {
    logger "Installing Filebeat..."

    $sys_type install filebeat-"${ELK_VERSION}" -y -q  
    if [ "$?" != 0 ]; then
        logger "Error: Filebeat installation failed"
        exit 1;
    else
        WAZUH_MAJOR="$(echo ${WAZUH_VERSION} | head -c 1)"

        curl -so /etc/filebeat/filebeat.yml ${resources_url}/resources/open-distro/filebeat/7.x/filebeat_all_in_one.yml --max-time 300  
        curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/master/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 
        chmod go+r /etc/filebeat/wazuh-template.json 
        
        curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module 
        mkdir -p /etc/filebeat/certs 
        cp /etc/elasticsearch/certs/root-ca.pem /etc/filebeat/certs/ 
        mv /etc/elasticsearch/certs/filebeat.key /etc/filebeat/certs/ 
        mv /etc/elasticsearch/certs/filebeat.pem /etc/filebeat/certs/ 
        # Start Filebeat
        startService "filebeat"
        logger "Done"
    fi
}

## Kibana
installKibana() {
    WAZUH_MAJOR="$(echo ${WAZUH_VERSION} | head -c 1)"
    logger "Installing Open Distro for Kibana..."
    $sys_type install opendistroforelasticsearch-kibana-${OPENDISTRO_VERSION} -y -q 
    if [ "$?" != 0 ]; then
        logger "Error: Kibana installation failed"
        exit 1;
    else
        curl -so /etc/kibana/kibana.yml ${resources_url}/resources/open-distro/kibana/7.x/kibana_all_in_one.yml --max-time 300 
        echo "telemetry.enabled: false" >> /etc/kibana/kibana.yml
        cd /usr/share/kibana 

        if [ "${STATUS_PACKAGES}" = "prod" ]; then
            sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/${WAZUH_MAJOR}.x/ui/kibana/wazuh_kibana-${WAZUH_VERSION}_${ELK_VERSION}.zip 
        elif [ "${STATUS_PACKAGES}" = "dev" ]; then
            sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages-dev.wazuh.com/pre-release/ui/kibana/wazuh_kibana-${WAZUH_VERSION}_${ELK_VERSION}-1.zip 
        fi
                
        if [ "$?" != 0 ]
        then
            logger "Error: Wazuh Kibana plugin could not be installed."
            exit 1;
        fi
        mkdir -p /etc/kibana/certs 
        mv /etc/elasticsearch/certs/kibana.key /etc/kibana/certs/ 
        mv /etc/elasticsearch/certs/kibana.pem /etc/kibana/certs/ 
        setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node 

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
        logger "The system must have at least 4Gb of RAM and 2 CPUs"
        exit 1;
    else
        logger "Starting the installation..."
    fi
}

checkInstallation() {

    logger "Checking the installation..."
    curl -XGET https://localhost:9200 -uadmin:admin -k --max-time 300 
    if [ "$?" != 0 ]; then
        logger "Error: Elasticsearch was not successfully installed."
        exit 1
    else
        logger "Elasticsearch installation succeeded."
    fi
    filebeat test output 
    if [ "$?" != 0 ]; then
        logger "Error: Filebeat was not successfully installed."
        exit 1;
    else
        logger "Filebeat installation succeeded."
    fi
    logger "Initializing Kibana (this may take a while)"
    until [[ "$(curl -XGET https://localhost/status -I -uadmin:admin -k -s | grep "200 OK")" ]]; do
        logger -ne $char
        sleep 10
    done
    logger $'\nInstallation finished'
}

cleanInstall(){
    rm -rf /etc/yum.repos.d/adoptopenjdk.repo
    rm -rf /etc/yum.repos.d/opendistroforelasticsearch-artifacts.repo
    rm -rf  /etc/yum.repos.d/wazuh.repo
    yum clean all
}
