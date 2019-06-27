Set_elastic_repository(){

    rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
    echo -e "[elasticsearch-${ELK_MAJOR}.x]\nname=Elasticsearch repository for ${ELK_MAJOR}.x packages\nbaseurl=https://artifacts.elastic.co/packages/${ELK_MAJOR}.x/yum\ngpgcheck=1\ngpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md" | tee /etc/yum.repos.d/elastic.repo

}

Install_elasticsearch(){

    yum install elasticsearch-${ELK_VERSION} -y
    systemctl daemon-reload
    systemctl enable elasticsearch.service

}
Install_filebeat_7(){

    yum install filebeat-${ELK_VERSION} -y
    curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/${repo_branch}/extensions/filebeat/7.x/filebeat.yml
    sed -i "s/YOUR_ELASTIC_SERVER_IP/localhost/" /etc/filebeat/filebeat.yml
    chmod go+r /etc/filebeat/filebeat.yml
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/${repo_branch}/extensions/elasticsearch/7.x/wazuh-template.json
    chmod go+r /etc/filebeat/wazuh-template.json

    systemctl daemon-reload
    systemctl enable filebeat.service
    systemctl start filebeat.service
}

Configure_elasticsearch(){

    cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
    cluster.name: wazuh-cluster
    node.name: ${HOSTNAME}
    path.data: /var/lib/elasticsearch
    path.logs: /var/log/elasticsearch
    bootstrap.memory_lock: true
    network.host: ["127.0.0.1"]
    discovery.zen.minimum_master_nodes: 1
EOF
}

Configure_jvm_elastic(){

    cat > /etc/elasticsearch/jvm.options << 'EOF'
    -Xms16g
    -Xmx16g
    -XX:+UseConcMarkSweepGC
    -XX:CMSInitiatingOccupancyFraction=75
    -XX:+UseCMSInitiatingOccupancyOnly
    -XX:+AlwaysPreTouch
    -Xss1m
    -Djava.awt.headless=true
    -Dfile.encoding=UTF-8
    -Djna.nosys=true
    -XX:-OmitStackTraceInFastThrow
    -Dio.netty.noUnsafe=true
    -Dio.netty.noKeySetOptimization=true
    -Dio.netty.recycler.maxCapacityPerThread=0
    -Dlog4j.shutdownHookEnabled=false
    -Dlog4j2.disable.jmx=true
    -Djava.io.tmpdir=${ES_TMPDIR}
    -XX:+HeapDumpOnOutOfMemoryError
    -XX:HeapDumpPath=/var/lib/elasticsearch
    -XX:ErrorFile=/var/log/elasticsearch/hs_err_pid%p.log
    8:-XX:+PrintGCDetails
    8:-XX:+PrintGCDateStamps
    8:-XX:+PrintTenuringDistribution
    8:-XX:+PrintGCApplicationStoppedTime
    8:-Xloggc:/var/log/elasticsearch/gc.log
    8:-XX:+UseGCLogFileRotation
    8:-XX:NumberOfGCLogFiles=32
    8:-XX:GCLogFileSize=64m
    9-:-Xlog:gc*,gc+age=trace,safepoint:file=/var/log/elasticsearch/gc.log:utctime,pid,tags:filecount=32,filesize=64m
    9-:-Djava.locale.providers=COMPAT
EOF
}

Configure_RAM(){

    ram_gb=$(free -g | awk "/^Mem:/{print ${ELK_VERSION}")
    ram=$(( ${ram_gb} / 2 ))
    if [ $ram -eq "0" ]; then ram=1; fi
    sed -i "s/-Xms16g/-Xms${ram}g/" /etc/elasticsearch/jvm.options
    sed -i "s/-Xmx16g/-Xms${ram}g/" /etc/elasticsearch/jvm.options
}

Configure_limitMEMLOCK(){

    mkdir -p /etc/systemd/system/elasticsearch.service.d/
    cat > /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf << 'EOF'
    [Service]
    LimitMEMLOCK=infinity
EOF
    systemctl daemon-reload
    systemctl start elasticsearch.service
}

Install_kibana(){

    yum install kibana-${ELK_VERSION} -y
}

Configure_kibana(){

    openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout /etc/kibana/kibana.key -out /etc/kibana/kibana.cert

    cat > /etc/kibana/kibana.yml << 'EOF'
    server.port: 443
    server.host: "0.0.0.0"
    server.ssl.enabled: true
    server.ssl.key: /etc/kibana/kibana.key
    server.ssl.certificate: /etc/kibana/kibana.cert
EOF

    # Allow Kibana to listen on port 443
    setcap 'CAP_NET_BIND_SERVICE=+eip' /usr/share/kibana/node/bin/node

    # Configuring Kibana default settings
    cat > /etc/default/kibana << 'EOF'
    ser="kibana"
    group="kibana"
    chroot="/"
    chdir="/"
    nice=""
    KILL_ON_STOP_TIMEOUT=0
    NODE_OPTIONS="--max-old-space-size=4096"
EOF
}

Install_kibana_app(){
    if [ "${STATUS_PACKAGES}" == "stable" ]; then
        #Wazuh-app production repository
        sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-${WAZUH_VERSION}_${ELK_VERSION}.zip
    fi

    if [ "${STATUS_PACKAGES}" == "unstable" ]; then
        # Wazuh-app pre-release repository
        sudo -u kibana NODE_OPTIONS="--max-old-space-size=3072" /usr/share/kibana/bin/kibana-plugin install https://packages-dev.wazuh.com/pre-release/app/kibana/wazuhapp-${WAZUH_VERSION}_${ELK_VERSION}.zip
    fi

    systemctl daemon-reload
    systemctl enable kibana.service
    systemctl start kibana

    while true; do

        STATUS=$(curl -XGET https://localhost/status -I -s -k | grep HTTP)
        if [[ "$STATUS" == *"200"* ]]; then
            echo "Kibana is running."
            break
        else
            echo "Waiting for Kibana"
            sleep 2
        fi
    done
    
}

Configure_kibana_app(){

    # Setting up the Kibana plugin API configuration
    api_config="/tmp/api_config.json"
    api_time=$(($(date +%s%N)/1000000))
    cat > ${api_config} << 'EOF'
    {
        "api_user": "foo",
        "api_password": "YmFy",
        "url": "https://localhost",
        "api_port": "55000",
        "insecure": "true",
        "component": "API",
        "cluster_info": {
        "manager": "wazuh-manager",
        "cluster": "disabled",
        "status": "disabled"
        },
        "extensions": {
        "oscap": true,
        "audit": true,
        "pci": true,
        "aws": true,
        "virustotal": true,
        "gdpr": true,
        "ciscat": true
        }
    }
EOF
    sed -i "s/\"manager\": \"wazuh-manager\",/\"manager\": \"$(hostname)\",/" ${api_config}
    curl -s -XPUT "http://localhost:9200/.wazuh/_doc/${api_time}" -H 'Content-Type: application/json' -d@${api_config}
    rm -f ${api_config}

    # Configuring default index pattern for Kibana
    default_index="/tmp/default_index.json"
    wazuh_major=`echo ${WAZUH_VERSION} | cut -d'.' -f 1`
    cat > ${default_index} << EOF
    {
        "changes": {
        "defaultIndex": "wazuh-alerts-${wazuh_major}.x-*"
        }
    }
EOF

    curl -k -POST "https://localhost/api/kibana/settings" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d@${default_index}
    rm -f ${default_index}

    # Configuring Kibana TimePicker
    curl -k -POST "https://localhost/api/kibana/settings" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d \
    '{"changes":{"timepicker:timeDefaults":"{\n  \"from\": \"now-24h\",\n  \"to\": \"now\",\n  \"mode\": \"quick\"}"}}'

    # Do not ask user to help providing usage statistics to Elastic
    curl -k -POST "https://localhost/api/telemetry/v1/optIn" -H "Content-Type: application/json" -H "kbn-xsrf: true" -d '{"enabled":false}'

}

Enable_geo_ip_7(){

    # Enable GeoIP
    geoip="/tmp/geoip.json"
    cat > ${geoip} << 'EOF'
    {
        "description" : "Add geoip info",
        "processors" : [
            {
                "geoip" : {
                    "field" : "@src_ip",
                    "target_field": "GeoLocation",
                    "properties": ["city_name", "country_name", "region_name", "location"],
                    "ignore_missing": true
                }
            },
            {
                "remove": {
                    "field": "@src_ip",
                    "ignore_missing": true
                }
            }
        ]
    }
EOF
    curl -X PUT "localhost:9200/_ingest/pipeline/geoip" -H 'Content-Type: application/json' -d@${geoip}

    # Enable GeoIP
    filebeat_config="/etc/filebeat/filebeat.yml"
    sed -i '/pipeline: geoip/s/^#//g' ${filebeat_config}
    systemctl restart filebeat
}

Install_jdk_6(){
    
    yum install -y java-1.8.0-openjdk
}

Insert_elasticsearch_template_6(){

  until $(curl "localhost:9200/?pretty" --max-time 2 --silent --output /dev/null); do
    echo "Waiting for Elasticsearch..."
    sleep 2
  done

  # Insert the template
  curl https://raw.githubusercontent.com/wazuh/wazuh/${repo_branch}/extensions/elasticsearch/wazuh-elastic6-template-alerts.json -so template.json
  sed -i 's#"index.refresh_interval": "5s"#"index.refresh_interval": "5s",\n    "number_of_shards": 1,\n    "number_of_replicas":0#g' template.json
  curl -s -XPUT "http://localhost:9200/_template/wazuh" -H 'Content-Type: application/json' -d @template.json
}

Install_logstash_6(){

    yum install logstash-$2 -y
    curl -so /etc/logstash/conf.d/01-wazuh.conf https://raw.githubusercontent.com/wazuh/wazuh/${repo_branch}/extensions/logstash/01-wazuh-local.conf
    usermod -a -G ossec logstash
    systemctl daemon-reload
    systemctl enable logstash.service
}

Configure_logstash_6(){

    # Configuring logstash.yml
    cat > /etc/logstash/logstash.yml << 'EOF'
    path.data: /var/lib/logstash
    path.logs: /var/log/logstash
    path.config: /etc/logstash/conf.d/*.conf
EOF

    # Configuring jvm.options
    cat > /etc/logstash/jvm.options << 'EOF'
    -Xms2g
    -Xmx2g
    -XX:+UseParNewGC
    -XX:+UseConcMarkSweepGC
    -XX:CMSInitiatingOccupancyFraction=75
    -XX:+UseCMSInitiatingOccupancyOnly
    -Djava.awt.headless=true
    -Dfile.encoding=UTF-8
    -Djruby.compile.invokedynamic=true
    -Djruby.jit.threshold=0
    -XX:+HeapDumpOnOutOfMemoryError
    -Djava.security.egd=file:/dev/urandom
EOF

    # Configuring RAM memory in jvm.options
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    ram=$(( ${ram_gb} / 8 ))
    if [ $ram -eq "0" ]; then ram=1; fi
    sed -i "s/-Xms2g/-Xms${ram}g/" /etc/logstash/jvm.options
    sed -i "s/-Xmx2g/-Xms${ram}g/" /etc/logstash/jvm.options

    systemctl daemon-reload
    systemctl enable logstash.service

}

Disable_repos_and_clean(){

    # Disable repositories
    sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
    sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo

    # Cleaning tasks
    yum clean all && rm -rf /var/cache/yum
    userdel -fr vagrant
}
elastic_stack_6(){

    Set_elastic_repository()
    Install_jdk_6()
    Install_elasticsearch()
    Configure_elasticsearch()
    Configure_jvm_elastic()
    Configure_RAM()
    Configure_limitMEMLOCK()
    Insert_elasticsearch_template_6()
    Install_logstash_6()
    Configure_logstash_6()
    Install_kibana()
    Configure_kibana()
    Install_kibana_app()
    Configure_kibana_app()
    Disable_repos_and_clean()
}

elastic_stack_7(){

    Set_elastic_repository()
    Install_filebeat_7()
    Install_elasticsearch()
    Configure_elasticsearch()
    Configure_jvm_elastic()
    Configure_RAM()
    Configure_limitMEMLOCK()
    Install_kibana()
    Configure_kibana()
    Install_kibana_app()
    Configure_kibana_app()
    Enable_geo_ip_7()
    Disable_repos_and_clean()
}