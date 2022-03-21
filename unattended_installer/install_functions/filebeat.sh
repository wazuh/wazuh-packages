# Wazuh installer - filebeat.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function filebeat_configure(){

    eval "curl -so /etc/filebeat/wazuh-template.json ${filebeat_wazuh_template} --max-time 300 ${debug}"
    eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
    eval "curl -s ${filebeat_wazuh_module} --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"
    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml ${debug}"
    else
        eval "installCommon_getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml ${debug}"
        if [ ${#indexer_node_names[@]} -eq 1 ]; then
            echo -e "\noutput.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
            echo "  - ${indexer_node_ips[0]}:9200" >> /etc/filebeat/filebeat.yml
        else
            echo -e "\noutput.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
            for i in "${indexer_node_ips[@]}"; do
                echo "  - ${i}:9200" >> /etc/filebeat/filebeat.yml
            done
        fi
    fi

    eval "mkdir /etc/filebeat/certs ${debug}"
    filebeat_copyCertificates

    eval "filebeat keystore create ${debug}"
    eval "echo admin | filebeat keystore add username --force --stdin ${debug}"
    eval "echo admin | filebeat keystore add password --force --stdin ${debug}"

    common_logger "Filebeat post-install configuration finished."
}

function filebeat_copyCertificates() {

    if [ -f "${tar_file}" ]; then
        if [ -n "${AIO}" ]; then
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} --wildcards wazuh-install-files/${server_node_names[0]}.pem ${debug} && mv ${filebeat_cert_path}/wazuh-install-files/${server_node_names[0]}.pem ${filebeat_cert_path}/filebeat.pem ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} --wildcards wazuh-install-files/${server_node_names[0]}-key.pem ${debug} && mv ${filebeat_cert_path}/wazuh-install-files/${server_node_names[0]}-key.pem ${filebeat_cert_path}/filebeat-key.pem ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/root-ca.pem && mv ${filebeat_cert_path}/wazuh-install-files/root-ca.pem ${filebeat_cert_path}/root-ca.pem ${debug}"
            eval "rm -rf ${filebeat_cert_path}/wazuh-install-files/"
        else
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/${winame}.pem && mv ${filebeat_cert_path}/wazuh-install-files/${winame}.pem ${filebeat_cert_path}/filebeat.pem ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/${winame}-key.pem && mv ${filebeat_cert_path}/wazuh-install-files/${winame}-key.pem ${filebeat_cert_path}/filebeat-key.pem ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/root-ca.pem && mv ${filebeat_cert_path}/wazuh-install-files/root-ca.pem ${filebeat_cert_path}/root-ca.pem ${debug}"
            eval "rm -rf ${filebeat_cert_path}/wazuh-install-files/"
        fi
        eval "chown root:root ${filebeat_cert_path}/*"
    else
        common_logger -e "No certificates found. Could not initialize Filebeat"
        exit 1;
    fi

}

function filebeat_install() {

    common_logger "Starting Filebeat installation."
    if [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install filebeat-${filebeat_version} ${debug}"
    elif [ "${sys_type}" == "yum" ]; then
        eval "yum install filebeat${sep}${filebeat_version} -y -q  ${debug}"
    elif [ "${sys_type}" == "apt-get" ]; then
        eval "DEBIAN_FRONTEND=noninteractive apt install filebeat${sep}${filebeat_version} -y -q  ${debug}"
    fi
    if [  "$?" != 0  ]; then
        common_logger -e "Filebeat installation failed"
        exit 1
    else
        common_logger "Filebeat installation finished."
        filebeatinstalled="1"
    fi

}
