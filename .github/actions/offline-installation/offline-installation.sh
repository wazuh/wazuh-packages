#!/bin/bash

# RPM / DEB
./wazuh-install.sh -dw rpm

curl -sO https://packages.wazuh.com/4.3/config.yml

sed -i -e '0,/<indexer-node-ip>/ s/<indexer-node-ip>/127.0.0.1/' config.yml
sed -i -e '0,/<wazuh-manager-ip>/ s/<indexer-node-ip>/127.0.0.1/' config.yml
sed -i -e '0,/<dashboard-node-ip>/ s/<indexer-node-ip>/127.0.0.1/' config.yml

curl -sO https://packages.wazuh.com/4.3/wazuh-certs-tool.sh
chmod 744 wazuh-certs-tool.sh
./wazuh-certs-tool.sh --all

tar xf wazuh-offline.tar.gz

# Wazuh indexer

# RPM
rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH
rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-indexer*.rpm

# DEB
# dpkg -i ./wazuh-offline/wazuh-packages/wazuh-indexer*.deb

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

enable_start_service("wazuh-indexer")

/usr/share/wazuh-indexer/bin/indexer-security-init.sh
curl -XGET https://localhost:9200 -u admin:admin -k

# Wazuh manager

# RPM
rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH
rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-manager*.rpm
# DEB
# dpkg -i ./wazuh-offline/wazuh-packages/wazuh-manager*.deb

enable_start_service("wazuh-manager")

systemctl status wazuh-manager

# Filebeat

# RPM
rpm -ivh ./wazuh-offline/wazuh-packages/filebeat*.rpm
# DEB
# dpkg -i ./wazuh-offline/wazuh-packages/filebeat*.deb

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

enable_start_service("filebeat")

filebeat test output
curl -k -u admin:admin "https://localhost:9200/_template/wazuh?pretty&filter_path=wazuh.settings.index.number_of_shards"

# Wazuh dashboard

# RPM
rpm --import ./wazuh-offline/wazuh-files/GPG-KEY-WAZUH
rpm -ivh ./wazuh-offline/wazuh-packages/wazuh-dashboard*.rpm
# DEB
dpkg -i ./wazuh-offline/wazuh-packages/wazuh-dashboard*.deb

NODE_NAME=dashboard
mkdir /etc/wazuh-dashboard/certs
mv -n wazuh-certificates/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
mv -n wazuh-certificates/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
cp wazuh-certificates/root-ca.pem /etc/wazuh-dashboard/certs/
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs

enable_start_service("wazuh-dashboard")

systemctl status wazuh-dashboard

curl -k -I -w "%{http_code}" https://localhost -o /dev/null --silent

function enable_start_service() {
    
    systemctl daemon-reload
    systemctl enable "${1}"
    systemctl start "${1}"

}