#!/bin/bash

# Check the system to differ between DEB and RPM
function check_system() {

    if [ -n "$(command -v yum)" ]; then
        sys_type="rpm"
        echo "RPM system detected."
    elif [ -n "$(command -v apt-get)" ]; then
        sys_type="deb"
        echo "DEB system detected."
    else
        echo "Error: could not detect the system."
        exit 1
    fi

}

function check_package() {

    if [ "${sys_type}" == "deb" ]; then
        if [ ! "$(dpkg --list | grep "${1}")" ]; then
            echo "The package "${1}" is not installed."
            exit 1
        fi
    elif [ "${sys_type}" == "rpm" ]; then
        if [ ! "$(rpm -qa | grep "${1}")" ]; then
            echo "The package "${1}" is not installed."
            exit 1
        fi
    fi

}

function enable_start_service() {
    
    systemctl daemon-reload
    systemctl enable "${1}"
    systemctl start "${1}"

    retries=0

    until [ "$(systemctl status "${1}" | grep "active")" ] || [ "${retries}" -eq 3 ]; do
        sleep 2
        retries=$((retries+1))
        systemctl start "${1}"
    done

    if [ ${retries} -eq 3 ]; then
        echo "The "${1}" service could not be started"
        exit 1
    fi

}

function download_packages(){

    if [ "${sys_type}" == "deb" ]; then
        ./wazuh-install.sh -dw deb
    elif [ "${sys_type}" == "rpm" ]; then
        ./wazuh-install.sh -dw rpm
    fi

    echo "Downloading the resources..."
    curl -sO https://packages.wazuh.com/4.3/config.yml

    sed -i -e '0,/<indexer-node-ip>/ s/<indexer-node-ip>/127.0.0.1/' config.yml
    sed -i -e '0,/<wazuh-manager-ip>/ s/<wazuh-manager-ip>/127.0.0.1/' config.yml
    sed -i -e '0,/<dashboard-node-ip>/ s/<dashboard-node-ip>/127.0.0.1/' config.yml

    curl -sO https://packages.wazuh.com/4.3/wazuh-certs-tool.sh
    chmod 744 wazuh-certs-tool.sh
    ./wazuh-certs-tool.sh --all

    tar xf wazuh-offline.tar.gz
    echo "Download finished."

    if [ ! -d ./wazuh-offline ]; then
        echo "Error: could not download the resources."
        exit 1
    fi

}

function indexer_installation(){

    if [ "${sys_type}" == "rpm" ]; then
        rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH
    fi
    
    install_package "wazuh-indexer" 
    check_package "wazuh-indexer"
    
    echo "Generating certificates of the Wazuh indexer..."
    NODE_NAME=node-1
    mkdir /etc/wazuh-indexer/certs
    mv -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
    mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
    mv wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/
    mv wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/
    cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/
    chmod 500 /etc/wazuh-indexer/certs
    chmod 400 /etc/wazuh-indexer/certs/*
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

    sed -i 's|\(network.host: \)"0.0.0.0"|\1"127.0.0.1"|' /etc/wazuh-indexer/opensearch.yml

    enable_start_service "wazuh-indexer"

    /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    eval "curl -XGET https://localhost:9200 -u admin:admin -k"
    if [ "${PIPESTATUS[0]}" != 0 ]; then
        echo "Error: The Wazuh indexer installation has failed."
        exit 1
    fi

}

function install_package() {

    if [ "${sys_type}" == "deb" ]; then
        dpkg -i ./wazuh-offline/wazuh-packages/"${1}"*.deb
    elif [ "${sys_type}" == "rpm" ]; then
        rpm -ivh ./wazuh-offline/wazuh-packages/"${1}"*.rpm
    fi    

}

function manager_installation(){

    install_package "wazuh-manager"
    check_package "wazuh-manager"

    enable_start_service "wazuh-manager"

}

function filebeat_installation(){

    install_package "filebeat"
    check_package "filebeat"

    cp ./wazuh-offline/wazuh-files/filebeat.yml /etc/filebeat/ &&\
    cp ./wazuh-offline/wazuh-files/wazuh-template.json /etc/filebeat/ &&\
    chmod go+r /etc/filebeat/wazuh-template.json

    sed -i 's|\("index.number_of_shards": \)".*"|\1 "1"|' /etc/filebeat/wazuh-template.json
    filebeat keystore create
    echo admin | filebeat keystore add username --stdin --force
    echo admin | filebeat keystore add password --stdin --force
    tar -xzf ./wazuh-offline/wazuh-files/wazuh-filebeat-0.2.tar.gz -C /usr/share/filebeat/module

    NODE_NAME=wazuh-1
    mkdir /etc/filebeat/certs
    mv -n wazuh-certificates/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
    mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
    cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/
    chmod 500 /etc/filebeat/certs
    chmod 400 /etc/filebeat/certs/*
    chown -R root:root /etc/filebeat/certs

    enable_start_service "filebeat"

    filebeat test output
    eval "curl -k -u admin:admin 'https://localhost:9200/_template/wazuh?pretty&filter_path=wazuh.settings.index.number_of_shards' | grep number_of_shards"
    if [ "${PIPESTATUS[0]}" != 0 ]; then
        echo "Error: The Filebeat installation has failed."
        exit 1
    fi

}

function dashboard_installation(){

    install_package "wazuh-dashboard"

    NODE_NAME=dashboard
    mkdir /etc/wazuh-dashboard/certs
    mv -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
    mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
    cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/
    chmod 500 /etc/wazuh-dashboard/certs
    chmod 400 /etc/wazuh-dashboard/certs/*
    chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

    enable_start_service "wazuh-dashboard"

    if [ "$(curl -k -I -w "%{http_code}" https://localhost -o /dev/null --silent)" -ne "302" ]; then
        echo "Error: The Wazuh dashboard installation has failed."
        exit 1
    fi

}