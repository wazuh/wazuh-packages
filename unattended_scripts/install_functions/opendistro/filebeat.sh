# Copyright (C) 2015-2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

f_cert_path="/etc/filebeat/certs/"

installFilebeat() {

    if [[ -f /etc/filebeat/filebeat.yml ]]; then
        logger -e "Filebeat is already installed in this node."
        exit 1;
    fi

    logger "Installing Filebeat..."
    
    if [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install filebeat-${elastic_oss_version} ${debug}"
    else
        eval "${sys_type} install filebeat${sep}${elastic_oss_version} -y -q  ${debug}"
    fi
    if [  "$?" != 0  ]
    then
        logger -e "Filebeat installation failed"
        exit 1;
    else
        filebeatinstalled="1"
    fi
}

copyCertificatesFilebeat() {

    if [ -f "${base_path}/certs.tar" ]; then
        if [ -n "${AIO}" ]; then
            eval "tar ${base_path}/certs.tar --wildcards filebeat* -C ${f_cert_path} ${debug}"
            eval "tar ${base_path}/certs.tar root-ca.pem -C ${f_cert_path} ${debug}"
        else
            eval "tar -xf ${base_path}/certs.tar ${winame}.pem -C ${f_cert_path} && mv ${f_cert_path}${winame}.pem ${f_cert_path}filebeat.pem ${debug}"
            eval "tar -xf ${base_path}/certs.tar ${winame}-key.pem -C ${f_cert_path} && mv ${f_cert_path}${winame}-key.pem ${f_cert_path}filebeat-key.pem ${debug}"
            eval "tar -xf ${base_path}/certs.tar root-ca.pem -C ${f_cert_path} ${debug}"
        fi
    else
        logger "No certificates found. Could not initialize Filebeat"
        exit 1;
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
    copyCertificatesFilebeat

    logger "Done"
    logger "Starting Filebeat..."
    startService filebeat
}

configureFilebeatAIO() {
        eval "getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml ${debug}"   
        eval "curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.0/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 ${debug}"
        eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
        eval "curl -s '${repobaseurl}'/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"
        eval "mkdir /etc/filebeat/certs ${debug}"
        copyCertificatesFilebeat

        # Start Filebeat
        logger "Starting Filebeat..."
        startService "filebeat"

        logger "Done"
}
