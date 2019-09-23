etc_elastic="/etc/elasticsearch"
etc_filebeat="/etc/filebeat"
etc_kibana="/etc/kibana"
usr_kibana="/usr/share/kibana"
RAW_TEMPLATE_URL1="https://raw.githubusercontent.com/wazuh/wazuh/v${WAZUH_VERSION}/extensions/elasticsearch/wazuh-elastic6-template-alerts.json"
RAW_TEMPLATE_URL2="https://raw.githubusercontent.com/wazuh/wazuh/v${WAZUH_VERSION}/extensions/elasticsearch/${ELK_MAJOR}.x/wazuh-template.json"

set_elastic_repository(){

    rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
    echo -e "[elasticsearch-${ELK_MAJOR}.x]\nname=Elasticsearch repository for ${ELK_MAJOR}.x packages\nbaseurl=https://artifacts.elastic.co/packages/${ELK_MAJOR}.x/yum\ngpgcheck=1\ngpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md" | tee -a /etc/yum.repos.d/elastic.repo
}

install_elasticsearch(){

    yum install elasticsearch-${ELK_VERSION} -y
    systemctl daemon-reload
    systemctl enable elasticsearch.service
}

install_filebeat_7(){

    yum install filebeat-${ELK_VERSION} -y
    cp -f ${config_files}/filebeat.yml ${etc_filebeat}/filebeat.yml

    sed -i "s/YOUR_ELASTIC_SERVER_IP/localhost/" ${etc_filebeat}/filebeat.yml
    curl -f ${RAW_TEMPLATE_URL2} -so ${etc_filebeat}/wazuh-template.json

    if [ ${ELK_MINOR} -ge 2 ]; then
        curl -s https://packages.wazuh.com/3.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz --no-same-owner -C /usr/share/filebeat/module --owner=0
    fi

    systemctl daemon-reload
    systemctl enable filebeat.service
    systemctl start filebeat.service
}

configure_elasticsearch(){

    cp -f ${config_files}/elasticsearch.yml ${etc_elastic}/elasticsearch.yml
}

configure_jvm_elastic(){

    cp -f ${config_files}/elasticsearch.jvm ${etc_elastic}/jvm.options
}

configure_RAM(){

    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    ram=$(( ${ram_gb} / 2 ))

    if [ ${ram} -eq "0" ]; then
        ram=1;
    fi

    sed -i "s/-Xms16g/-Xms${ram}g/" ${etc_elastic}/jvm.options
    sed -i "s/-Xmx16g/-Xmx${ram}g/" ${etc_elastic}/jvm.options
}

configure_limitMEMLOCK(){

    mkdir -p /etc/systemd/system/elasticsearch.service.d/
    cp -f ${config_files}/elasticsearch.conf /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf

    systemctl daemon-reload
    systemctl start elasticsearch.service
}

install_kibana(){

    yum install kibana-${ELK_VERSION} -y
}

configure_kibana(){

    openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout ${etc_kibana}/kibana.key -out ${etc_kibana}/kibana.cert

    cp -f ${config_files}/kibana.yml  ${etc_kibana}/kibana.yml

    # Allow Kibana to listen on port 443
    setcap 'CAP_NET_BIND_SERVICE=+eip' ${usr_kibana}/node/bin/node

    # Configuring Kibana default settings
    cp -f ${config_files}/kibana  /etc/default/kibana
}

install_kibana_app(){

    if [ "${STATUS_PACKAGES}" = "stable" ]; then
        #Wazuh-app production repository
        sudo -u kibana ${usr_kibana}/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-${WAZUH_VERSION}_${ELK_VERSION}.zip
    fi

    if [ "${STATUS_PACKAGES}" = "unstable" ]; then
        # Wazuh-app pre-release repository
        sudo -u kibana ${usr_kibana}/bin/kibana-plugin install https://packages-dev.wazuh.com/pre-release/app/kibana/wazuhapp-${WAZUH_VERSION}_${ELK_VERSION}.zip
    fi

    systemctl daemon-reload
    systemctl enable kibana.service
    systemctl start kibana

    until [[ "$(curl -XGET https://localhost/status -I -s -k | grep HTTP)" == *"200"* ]]; do
        echo "Waiting for Kibana..."
        sleep 2
    done
}

configure_kibana_app(){

    # Setting up the Kibana plugin API configuration
    api_config="/tmp/api_config.json"
    api_time=$(($(date +%s%N)/1000000))

    cp -f ${config_files}/api_config.json  ${api_config}

    sed -i "s/\"manager\": \"wazuh-manager\",/\"manager\": \"$(hostname)\",/" ${api_config}
    curl -f -s -XPUT "http://localhost:9200/.wazuh/_doc/${api_time}" -H 'Content-Type: application/json' -d@${api_config}
    rm -f ${api_config}

    # Configuring default index pattern for Kibana
    default_index="/tmp/default_index.json"
    wazuh_major=`echo ${WAZUH_VERSION} | cut -d'.' -f 1`

    cp -f ${config_files}/default_index.json  ${default_index}
    sed -i "s/{wazuh_major}/${wazuh_major}/g" ${default_index}

    curl -f -k -POST "https://localhost/api/kibana/settings" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d@${default_index}
    rm -f ${default_index}

    # Configuring Kibana TimePicker
    curl -f -k -POST "https://localhost/api/kibana/settings" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d \
    '{"changes":{"timepicker:timeDefaults":"{\n  \"from\": \"now-24h\",\n  \"to\": \"now\",\n  \"mode\": \"quick\"}"}}'

    # Do not ask user to help providing usage statistics to Elastic
    if [ $ELK_MAJOR -eq "6" ]; then
        curl -f -k -POST "https://localhost/api/telemetry/v1/optIn" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d '{"enabled":false}'
    fi
}

install_jdk_6(){

    yum install -y java-1.8.0-openjdk
}

insert_elasticsearch_template_6(){

    wazuh_major=`echo ${WAZUH_VERSION} | cut -d'.' -f 1`
    wazuh_minor=`echo ${WAZUH_VERSION} | cut -d'.' -f 2`
    wazuh_changes=`echo ${WAZUH_VERSION} | cut -d'.' -f 3`

    until $(curl "localhost:9200/?pretty" --max-time 2 --silent --output /dev/null); do
        echo "Waiting for Elasticsearch..."
        sleep 2
    done

    # Insert the template
    if curl -f ${RAW_TEMPLATE_URL1} -so template.json ; then
        echo "Downloading Elastic-template for Wazuh v${WAZUH_VERSION} and Elastic ${ELK_VERSION}"
    elif curl -f ${RAW_TEMPLATE_URL2} -so template.json ; then
        echo "Downloading Elastic-template for Wazuh v${WAZUH_VERSION} and Elastic ${ELK_VERSION}"
    else
        exit 1
    fi

    sed -i 's#"index.refresh_interval": "5s"#"index.refresh_interval": "5s",\n    "number_of_shards": 1,\n    "number_of_replicas":0#g' template.json
    curl -f -s -XPUT "http://localhost:9200/_template/wazuh" -H 'Content-Type: application/json' -d @template.json
}

install_logstash_6(){

    yum install logstash-${ELK_VERSION} -y
    curl -f -so /etc/logstash/conf.d/01-wazuh.conf https://raw.githubusercontent.com/wazuh/wazuh/${repo_branch}/extensions/logstash/6.x/01-wazuh-local.conf
    usermod -a -G ossec logstash
    systemctl daemon-reload
    systemctl enable logstash.service
}

configure_logstash_6(){

    # Configuring logstash.yml
    cp -f ${config_files}/logstash.yml /etc/logstash/logstash.yml

    # Configuring jvm.options
    cp -f ${config_files}/logstash.jvm /etc/logstash/jvm.options

    # Configuring RAM memory in jvm.options
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    ram=$(( ${ram_gb} / 8 ))

    if [ ${ram} -eq "0" ]; then
        ram=1;
    fi

    sed -i "s/-Xms2g/-Xms${ram}g/" /etc/logstash/jvm.options
    sed -i "s/-Xmx2g/-Xmx${ram}g/" /etc/logstash/jvm.options

    systemctl daemon-reload
    systemctl enable logstash.service

}

disable_repos_and_clean(){

    # Set Wazuh production repository
    if [ "${STATUS_PACKAGES}" = "unstable" ]; then
        echo -e '[wazuh_repo]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=Wazuh repository \nbaseurl=https://packages.wazuh.com/3.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo
    fi

    # Disable repositories
    yum-config-manager --disable elasticsearch-${ELK_MAJOR}.x
    if [ "${STATUS_PACKAGES}" = "stable" ]; then
        yum-config-manager --disable wazuh_repo
    else
        yum-config-manager --disable wazuh_repo_dev
    fi

    # Cleaning tasks
    yum clean all && rm -rf /var/cache/yum
    userdel -fr vagrant
}
elastic_stack_6(){

    set_elastic_repository
    install_jdk_6
    install_elasticsearch
    configure_elasticsearch
    configure_jvm_elastic
    configure_RAM
    configure_limitMEMLOCK
    insert_elasticsearch_template_6
    install_logstash_6
    configure_logstash_6
    install_kibana
    configure_kibana
    install_kibana_app
    configure_kibana_app
    disable_repos_and_clean
}

elastic_stack_7(){

    set_elastic_repository
    install_filebeat_7
    install_elasticsearch
    configure_elasticsearch
    configure_jvm_elastic
    configure_RAM
    configure_limitMEMLOCK
    install_kibana
    configure_kibana
    install_kibana_app
    configure_kibana_app
    disable_repos_and_clean
}