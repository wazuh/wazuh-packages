# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

installFilebeat() {

    logger "Starting filebeat installation."
    
    if [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install filebeat-${elasticsearch_oss_version} ${debug}"
    else
        eval "${sys_type} install filebeat${sep}${elasticsearch_oss_version} -y -q  ${debug}"
    fi
    if [  "$?" != 0  ]
    then
        logger -e "Filebeat installation failed"
        exit 1;
    else
        logger "Filebeat installation finished."
        filebeatinstalled="1"
    fi
}

configureFilebeat() {

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
    eval "mv ${base_path}/certs/${winame}.pem /etc/filebeat/certs/filebeat.pem ${debug}"
    eval "mv ${base_path}/certs/${winame}-key.pem /etc/filebeat/certs/filebeat-key.pem ${debug}"
    eval "cp ${base_path}/certs/root-ca.pem /etc/filebeat/certs/ ${debug}"

    logger "Filebeat post-install configuration finished."
}

configureFilebeatAIO() {
    eval "getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml ${debug}"
    eval "curl -so /etc/filebeat/wazuh-template.json ${filebeat_wazuh_template} --max-time 300 ${debug}"
    eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
    eval "curl -s ${filebeat_wazuh_module} --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"
    eval "mkdir /etc/filebeat/certs ${debug}"
    eval "cp ${base_path}/certs/root-ca.pem /etc/filebeat/certs/ ${debug}"
    eval "cp ${base_path}/certs/filebeat* /etc/filebeat/certs/ ${debug}"

    logger "Filebeat post-install configuration finished."

}
