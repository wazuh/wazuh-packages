# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

f_cert_path="/etc/filebeat/certs/"

function configureFilebeat() {

    eval "getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml ${debug}"
    eval "curl -so /etc/filebeat/wazuh-template.json ${filebeat_wazuh_template} --max-time 300 ${debug}"
    eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
    eval "curl -s ${filebeat_wazuh_module} --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"


    if [ ${#elasticsearch_node_names[@]} -eq 1 ]; then
        echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
        echo "  - ${elasticsearch_node_ips[0]}"  >> /etc/filebeat/filebeat.yml
    else
        echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
        for i in ${elasticsearch_node_ips[@]}; do
                echo "  - ${i}" >> /etc/filebeat/filebeat.yml
        done
    fi

    eval "mkdir /etc/filebeat/certs ${debug}"
    copyCertificatesFilebeat

    logger "Filebeat post-install configuration finished."
}

function configureFilebeatAIO() {

    eval "getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml ${debug}"
    eval "curl -so /etc/filebeat/wazuh-template.json ${filebeat_wazuh_template} --max-time 300 ${debug}"
    eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
    eval "curl -s ${filebeat_wazuh_module} --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"
    eval "mkdir /etc/filebeat/certs ${debug}"
    copyCertificatesFilebeat

    logger "Filebeat post-install configuration finished."

}

function copyCertificatesFilebeat() {

    if [ -f "${base_path}/certs.tar" ]; then
        if [ -n "${AIO}" ]; then
            eval "tar -xf ${base_path}/certs.tar -C ${f_cert_path} --wildcards ./filebeat* ${debug}"
            eval "tar -xf ${base_path}/certs.tar -C ${f_cert_path} ./root-ca.pem ${debug}"
        else
            eval "tar -xf ${base_path}/certs.tar -C ${f_cert_path} ./${winame}.pem && mv ${f_cert_path}${winame}.pem ${f_cert_path}filebeat.pem ${debug}"
            eval "tar -xf ${base_path}/certs.tar -C ${f_cert_path} ./${winame}-key.pem && mv ${f_cert_path}${winame}-key.pem ${f_cert_path}filebeat-key.pem ${debug}"
            eval "tar -xf ${base_path}/certs.tar -C ${f_cert_path} ./root-ca.pem ${debug}"
        fi
    else
        logger -e "No certificates found. Could not initialize Filebeat"
        exit 1;
    fi
}

function installFilebeat() {

    logger "Starting filebeat installation."
    
    if [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install filebeat-${elasticsearch_oss_version} ${debug}"
    else
        eval "${sys_type} install filebeat${sep}${elasticsearch_oss_version} -y -q  ${debug}"
    fi
    if [  "$?" != 0  ]
    then
        logger -e "Filebeat installation failed"
        exit 1
    else
        logger "Filebeat installation finished."
        filebeatinstalled="1"
    fi
}
