# Wazuh installer - filebeat.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

readonly f_cert_path="/etc/filebeat/certs/"

function filebeat_configure(){

    eval "curl -so /etc/filebeat/wazuh-template.json ${filebeat_wazuh_template} --max-time 300 ${debug}"
    eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
    eval "curl -s ${filebeat_wazuh_module} --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"
    if [ -n "${AIO}" ]; then
        eval "common_getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml ${debug}"
    else
        eval "common_getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml ${debug}"
        if [ ${#indexer_node_names[@]} -eq 1 ]; then
            echo -e "\noutput.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
            echo "  - ${indexer_node_ips[0]}:9700" >> /etc/filebeat/filebeat.yml
        else
            echo -e "\noutput.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
            for i in "${indexer_node_ips[@]}"; do
                echo "  - ${i}:9700" >> /etc/filebeat/filebeat.yml
            done
        fi
    fi

    eval "mkdir /etc/filebeat/certs ${debug}"
    filebeat_copyCertificates

    logger "Filebeat post-install configuration finished."
}

function filebeat_copyCertificates() {

    if [ -f "${tar_file}" ]; then
        if [ -n "${AIO}" ]; then
            eval "tar -xf ${tar_file} -C ${f_cert_path} --wildcards ./filebeat* ${debug}"
            eval "tar -xf ${tar_file} -C ${f_cert_path} ./root-ca.pem ${debug}"
        else
            eval "tar -xf ${tar_file} -C ${f_cert_path} ./${winame}.pem && mv ${f_cert_path}${winame}.pem ${f_cert_path}filebeat.pem ${debug}"
            eval "tar -xf ${tar_file} -C ${f_cert_path} ./${winame}-key.pem && mv ${f_cert_path}${winame}-key.pem ${f_cert_path}filebeat-key.pem ${debug}"
            eval "tar -xf ${tar_file} -C ${f_cert_path} ./root-ca.pem ${debug}"
        fi
    else
        logger -e "No certificates found. Could not initialize Filebeat"
        exit 1;
    fi

}

function filebeat_install() {

    logger "Starting filebeat installation."
    if [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install filebeat-${filebeat_version} ${debug}"
    elif [ "${sys_type}" == "yum" ]; then
        eval "yum install filebeat${sep}${filebeat_version} -y -q  ${debug}"
    elif [ "${sys_type}" == "apt-get" ]; then
        eval "DEBIAN_FRONTEND=noninteractive apt install filebeat${sep}${filebeat_version} -y -q  ${debug}"
    fi
    if [  "$?" != 0  ]; then
        logger -e "Filebeat installation failed."
        filebeatinstalled="manager"
        common_rollBack
        exit 1
    else
        logger "Filebeat installation finished."
        filebeatinstalled="1"
    fi

}
