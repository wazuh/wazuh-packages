# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

installFilebeat() {

    logger "Installing Filebeat..."
    
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
        logger "Filebeat installed"
        filebeatinstalled="1"
        ((progressbar_status++))
    fi
}

configureFilebeat() {

    eval "getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml ${debug}"
    eval "curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.2/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 ${debug}"
    eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
    eval "curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"

    nh=$(awk -v RS='' '/network.host:/' ./config.yml)

    if [ -n "$nh" ]
    then
        nhr="network.host: "
        nip="${nh//$nhr}"
        echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
        echo "  - ${nip}"  >> /etc/filebeat/filebeat.yml
    else
        echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
        sh=$(awk -v RS='' '/discovery.seed_hosts:/' ./config.yml)
        shr="discovery.seed_hosts:"
        rm="- "
        sh="${sh//$shr}"
        sh="${sh//$rm}"
        for line in $sh; do
                echo "  - ${line}" >> /etc/filebeat/filebeat.yml
        done
    fi

    eval "mkdir /etc/filebeat/certs ${debug}"
    eval "mv ${base_path}/certs/${winame}.pem /etc/filebeat/certs/filebeat.pem ${debug}"
    eval "mv ${base_path}/certs/${winame}-key.pem /etc/filebeat/certs/filebeat-key.pem ${debug}"
    eval "cp ${base_path}/certs/root-ca.pem /etc/filebeat/certs/ ${debug}"

    logger "Done"
    startService filebeat
    ((progressbar_status++))
}

configureFilebeatAIO() {
        eval "getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml ${debug}"   
        eval "curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.0/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 ${debug}"
        eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
        eval "curl -s '${repobaseurl}'/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"
        eval "mkdir /etc/filebeat/certs ${debug}"
        eval "cp ${base_path}/certs/root-ca.pem /etc/filebeat/certs/ ${debug}"
        eval "cp ${base_path}/certs/filebeat* /etc/filebeat/certs/ ${debug}"

        startService "filebeat"

        logger "Done"
        ((progressbar_status++))
}
