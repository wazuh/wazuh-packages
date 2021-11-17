installFilebeat() {

    if [[ -f /etc/filebeat/filebeat.yml ]]; then
        echo "Filebeat is already installed in this node."
        exit 1;
    fi

    logger "Installing Filebeat..."
    
    if [ ${sys_type} == "zypper" ]; then
        eval "zypper -n install filebeat-${ELK_VER} ${debug}"
    else
        eval "${sys_type} install filebeat${sep}${ELK_VER} -y -q  ${debug}"
    fi
    if [  "$?" != 0  ]
    then
        echo "Error: Filebeat installation failed"
        exit 1;
    else
        filebeatinstalled="1"
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

    eval "mv ./certs/${winame}.pem /etc/filebeat/certs/filebeat.pem ${debug}"
    eval "mv ./certs/${winame}-key.pem /etc/filebeat/certs/filebeat-key.pem ${debug}"
    eval "cp ./certs/root-ca.pem /etc/filebeat/certs/ ${debug}"

    logger "Done"
    echo "Starting Filebeat..."
    startService filebeat
}

configureFilebeatAIO() {
        eval "getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml ${debug}"   
        eval "curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.0/extensions/elasticsearch/7.x/wazuh-template.json --max-time 300 ${debug}"
        eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
        eval "curl -s '${repobaseurl}'/filebeat/wazuh-filebeat-0.1.tar.gz --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"
        eval "mkdir /etc/filebeat/certs ${debug}"
        eval "cp ./certs/root-ca.pem /etc/filebeat/certs/ ${debug}"
        eval "cp ./certs/filebeat* /etc/filebeat/certs/ ${debug}"

        # Start Filebeat
        startService "filebeat"

        logger "Done"
}
