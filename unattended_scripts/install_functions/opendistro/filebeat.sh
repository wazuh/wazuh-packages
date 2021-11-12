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

    nh=$(awk -v RS='' '/network.host:/' ~/config.yml)

    if [ -n "$nh" ]
    then
        nhr="network.host: "
        nip="${nh//$nhr}"
        echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
        echo "  - ${nip}"  >> /etc/filebeat/filebeat.yml
    else
        echo "output.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
        sh=$(awk -v RS='' '/discovery.seed_hosts:/' ~/config.yml)
        shr="discovery.seed_hosts:"
        rm="- "
        sh="${sh//$shr}"
        sh="${sh//$rm}"
        for line in $sh; do
                echo "  - ${line}" >> /etc/filebeat/filebeat.yml
        done
    fi

    eval "mkdir /etc/filebeat/certs ${debug}"
    eval "cp ./certs.tar /etc/filebeat/certs/ ${debug}"
    eval "cd /etc/filebeat/certs/ ${debug}"
    eval "tar -xf certs.tar ${iname}.pem ${iname}.key root-ca.pem ${debug}"
    if [ ${iname} != "filebeat" ]
    then
        eval "mv /etc/filebeat/certs/${iname}.pem /etc/filebeat/certs/filebeat.pem ${debug}"
        eval "mv /etc/filebeat/certs/${iname}.key /etc/filebeat/certs/filebeat.key ${debug}"
    fi
    logger "Done"
    echo "Starting Filebeat..."
    eval "systemctl daemon-reload ${debug}"
    eval "systemctl enable filebeat.service ${debug}"
    eval "systemctl start filebeat.service ${debug}"
}

configureFilebeatAIO() {
        eval "curl -so /etc/filebeat/filebeat.yml ${resources}/open-distro/filebeat/7.x/filebeat_unattended.yml --max-time 300  ${debug}"   
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