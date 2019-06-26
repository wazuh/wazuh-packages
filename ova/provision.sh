# Variables
repo_branch=$(echo "$1" | cut -c1-3)
repo_baseurl=$(echo "$1" | cut -c1-2)

install_wazuh() {

  # $3 is status repository if:
  # $3 = STABLE   -> Access to production repositories
  # $3 = UNSTABLE -> Access to pre-release repositories

  if [ "$3" == "stable" ]; then
    # Wazuh production repository
    echo -e '[wazuh_repo]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=Wazuh repository \nbaseurl=https://packages.wazuh.com/3.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo

  fi

  if [ "$3" == "unstable" ]; then
    # Wazuh pre-release repository
    echo -e '[wazuh_repo_dev]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-dev.wazuh.com/pre-release/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo

  fi

  # Install nodejs
  curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
  yum install nodejs -y

  # Install and stop Manager and API
  yum install wazuh-manager-$1 wazuh-api-$1 -y

  manager_config="${4}/etc/ossec.conf"

  # Disabling agent components and cleaning configuration file
  sed -i '/<rootcheck>/,/<\/rootcheck>/d' ${manager_config}
  sed -i '/<wodle name="open-scap">/,/<\/wodle>/d' ${manager_config}
  sed -i '/<wodle name="cis-cat">/,/<\/wodle>/d' ${manager_config}
  sed -i '/<wodle name="osquery">/,/<\/wodle>/d' ${manager_config}
  sed -i '/<wodle name="syscollector">/,/<\/wodle>/d' ${manager_config}
  sed -i '/<syscheck>/,/<\/syscheck>/d' ${manager_config}
  sed -i '/<localfile>/,/<\/localfile>/d' ${manager_config}
  sed -i '/<!--.*-->/d' ${manager_config}
  sed -i '/<!--/,/-->/d' ${manager_config}
  sed -i '/^$/d' ${manager_config}


  # Configuring registration service
  sed -i '/<auth>/,/<\/auth>/d' ${manager_config}

  cat >> ${manager_config} << EOF
  <ossec_config>
    <auth>
      <disabled>no</disabled>
      <port>1515</port>
      <use_source_ip>no</use_source_ip>
      <force_insert>yes</force_insert>
      <force_time>0</force_time>
      <purge>yes</purge>
      <use_password>no</use_password>
      <limit_maxagents>yes</limit_maxagents>
      <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
      <!-- <ssl_agent_ca></ssl_agent_ca> -->
      <ssl_verify_host>no</ssl_verify_host>
      <ssl_manager_cert>${4}/etc/sslmanager.cert</ssl_manager_cert>
      <ssl_manager_key>${4}/etc/sslmanager.key</ssl_manager_key>
      <ssl_auto_negotiate>no</ssl_auto_negotiate>
    </auth>
  </ossec_config>
EOF

  # Configuring Wazuh API user and password
  cd ${4}/api/configuration/auth
  node htpasswd -b -c user foo bar

  # Enable Wazuh API SSL and configure listening port
  api_ssl_dir="${4}/api/configuration/ssl"
  openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout ${api_ssl_dir}/server.key -out ${api_ssl_dir}/server.crt
  sed -i "s/config.https = \"no\";/config.https = \"yes\";/" ${4}/api/configuration/config.js

  systemctl stop wazuh-manager
  systemctl stop wazuh-api

  find ${4}/logs -name *.log -exec : > {} \;
  rm -rf ${4}/logs/{archives,alerts,cluster,firewall,ossec}/*
  rm -rf ${4}/stats/*
}

elasticsearch_7() {

  # Elastic 7 repository
  rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
  echo -e '[elasticsearch-7.x]\nname=Elasticsearch repository for 7.x packages\nbaseurl=https://artifacts.elastic.co/packages/7.x/yum\ngpgcheck=1\ngpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md' | tee /etc/yum.repos.d/elastic.repo

  # Filebeat
  yum install filebeat-$2 -y
  curl -so /etc/filebeat/filebeat.yml https://raw.githubusercontent.com/wazuh/wazuh/${repo_branch}/extensions/filebeat/7.x/filebeat.yml
  sed -i "s/YOUR_ELASTIC_SERVER_IP/localhost/" /etc/filebeat/filebeat.yml
  chmod go+r /etc/filebeat/filebeat.yml
  curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/${repo_branch}/extensions/elasticsearch/7.x/wazuh-template.json
  chmod go+r /etc/filebeat/wazuh-template.json

  systemctl daemon-reload
  systemctl enable filebeat.service
  systemctl start filebeat.service

  yum install elasticsearch-$2 -y
  systemctl daemon-reload
  systemctl enable elasticsearch.service

  # Configuring elasticsearch.yml
  cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
  cluster.name: wazuh-cluster
  node.name: ${HOSTNAME}
  path.data: /var/lib/elasticsearch
  path.logs: /var/log/elasticsearch
  bootstrap.memory_lock: true
  network.host: ["127.0.0.1"]
  discovery.zen.minimum_master_nodes: 1
EOF

  # Configuring jvm.options
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

  # Configuring RAM memory in jvm.options
  ram_gb=$(free -g | awk '/^Mem:/{print $2}')
  ram=$(( ${ram_gb} / 2 ))
  if [ $ram -eq "0" ]; then ram=1; fi
  sed -i "s/-Xms16g/-Xms${ram}g/" /etc/elasticsearch/jvm.options
  sed -i "s/-Xmx16g/-Xms${ram}g/" /etc/elasticsearch/jvm.options

  # Configuring Elasticsearch LimitMEMLOCK
  mkdir -p /etc/systemd/system/elasticsearch.service.d/
  cat > /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf << 'EOF'
  [Service]
  LimitMEMLOCK=infinity
EOF
  systemctl daemon-reload

  # Starting Elasticsearch
  systemctl start elasticsearch.service

  # Kibana
  yum install kibana-$2 -y

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

  if [ "$3" == "stable" ]; then
    #Wazuh-app production repository
    sudo -u kibana /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-$1_$2.zip
  fi

  if [ "$3" == "unstable" ]; then
    # Wazuh-app pre-release repository
    sudo -u kibana NODE_OPTIONS="--max-old-space-size=3072" /usr/share/kibana/bin/kibana-plugin install https://packages-dev.wazuh.com/pre-release/app/kibana/wazuhapp-$1_$2.zip
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
  wazuh_major=`echo $1 | cut -d'.' -f 1`
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
  cat > ${filebeat_config} << 'EOF'
  # Wazuh - Filebeat configuration file

  filebeat.inputs:
    - type: log
      paths:
        - '/var/ossec/logs/alerts/alerts.json'

  setup.template.json.enabled: true
  setup.template.json.path: "/etc/filebeat/wazuh-template.json"
  setup.template.json.name: "wazuh"
  setup.template.overwrite: true

  processors:
    - decode_json_fields:
        fields: ['message']
        process_array: true
        max_depth: 200
        target: ''
        overwrite_keys: true
    - drop_fields:
        fields: ['message', 'ecs', 'beat', 'input_type', 'tags', 'count', '@version', 'log', 'offset', 'type', 'host']
    - rename:
        fields:
          - from: "data.aws.sourceIPAddress"
            to: "@src_ip"
        ignore_missing: true
        fail_on_error: false
        when:
          regexp:
            data.aws.sourceIPAddress: \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
    - rename:
        fields:
          - from: "data.srcip"
            to: "@src_ip"
        ignore_missing: true
        fail_on_error: false
        when:
          regexp:
            data.srcip: \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b
    - rename:
        fields:
          - from: "data.win.eventdata.ipAddress"
            to: "@src_ip"
        ignore_missing: true
        fail_on_error: false
        when:
          regexp:
            data.win.eventdata.ipAddress: \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b

  output.elasticsearch:
    hosts: ['http://localhost:9200']
    pipeline: geoip
    indices:
      - index: 'wazuh-alerts-3.x-%{+yyyy.MM.dd}'
EOF

  systemctl restart filebeat

}

elasticsearch_6() {

  # Java + ELK
  yum install -y java-1.8.0-openjdk 


  # Elastic repository
  rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
  echo -e '[elasticsearch-6.x]\nname=Elasticsearch repository for 6.x packages\nbaseurl=https://artifacts.elastic.co/packages/6.x/yum\ngpgcheck=1\ngpgkey=https://  artifacts.elastic.co/GPG-KEY-elasticsearch\nenabled=1\nautorefresh=1\ntype=rpm-md' | tee /etc/yum.repos.d/elastic.repo

  yum install elasticsearch-$2 -y
  systemctl daemon-reload
  systemctl enable elasticsearch.service

  # Configuring elasticsearch.yml
  cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
  cluster.name: wazuh-cluster
  node.name: ${HOSTNAME}
  path.data: /var/lib/elasticsearch
  path.logs: /var/log/elasticsearch
  bootstrap.memory_lock: true
  network.host: ["127.0.0.1"]
  discovery.zen.minimum_master_nodes: 1
EOF

  # Configuring jvm.options
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



  # Configuring RAM memory in jvm.options
  ram_gb=$(free -g | awk '/^Mem:/{print $2}')
  ram=$(( ${ram_gb} / 2 ))
  if [ $ram -eq "0" ]; then ram=1; fi
  sed -i "s/-Xms16g/-Xms${ram}g/" /etc/elasticsearch/jvm.options
  sed -i "s/-Xmx16g/-Xms${ram}g/" /etc/elasticsearch/jvm.options

  # Configuring Elasticsearch LimitMEMLOCK
  mkdir -p /etc/systemd/system/elasticsearch.service.d/
  cat > /etc/systemd/system/elasticsearch.service.d/elasticsearch.conf << 'EOF'
  [Service]
  LimitMEMLOCK=infinity
EOF
  systemctl daemon-reload

  # Starting Elasticsearch
  systemctl start elasticsearch.service
  until $(curl "localhost:9200/?pretty" --max-time 2 --silent --output /dev/null); do
    echo "Waiting for Elasticsearch..."
    sleep 2
  done

  # Insert the template
  curl https://raw.githubusercontent.com/wazuh/wazuh/${repo_branch}/extensions/elasticsearch/wazuh-elastic6-template-alerts.json -so template.json
  sed -i 's#"index.refresh_interval": "5s"#"index.refresh_interval": "5s",\n    "number_of_shards": 1,\n    "number_of_replicas":0#g' template.json
  curl -s -XPUT "http://localhost:9200/_template/wazuh" -H 'Content-Type: application/json' -d @template.json

  # Logstash
  yum install logstash-$2 -y
  curl -so /etc/logstash/conf.d/01-wazuh.conf https://raw.githubusercontent.com/wazuh/wazuh/${repo_branch}/extensions/logstash/01-wazuh-local.conf
  usermod -a -G ossec logstash
  systemctl daemon-reload
  systemctl enable logstash.service

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


  # Kibana
  systemctl stop elasticsearch
  yum install kibana-$2 -y


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


  if [ "$3" == "stable" ]; then
    #Wazuh-app production repository
    sudo -u kibana NODE_OPTIONS="--max-old-space-size=3072" /usr/share/kibana/bin/kibana-plugin install https://packages.wazuh.com/wazuhapp/wazuhapp-$1_$2.zip

  fi

  if [ "$3" == "unstable" ]; then
    # Wazuh-app pre-release repository
    sudo -u kibana NODE_OPTIONS="--max-old-space-size=3072" /usr/share/kibana/bin/kibana-plugin install https://packages-dev.wazuh.com/pre-release/app/kibana/wazuhapp-$1_$2.zip
  fi



  # Starting Elasticsearch
  systemctl start elasticsearch.service
  until $(curl "localhost:9200/?pretty" --max-time 2 --silent --output /dev/null); do
    echo "Waiting for Elasticsearch..."
    sleep 2
  done

}

# Setting wazuh default root password
yes wazuh | passwd root
hostname wazuhmanager

# Ssh config
sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# Dependences
yum install openssl -y

install_wazuh $1 $2 $3 $4

if elastic 7 or elastic 6

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
curl -s -XPUT "http://localhost:9200/.wazuh/wazuh-configuration/${api_time}" -H 'Content-Type: application/json' -d@${api_config}
rm -f ${api_config}

# Configuring default index pattern for Kibana
default_index="/tmp/default_index.json"
wazuh_major=`echo $1 | cut -d'.' -f 1`
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

# Disable repositories
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo

# Cleaning tasks
yum clean all && rm -rf /var/cache/yum
userdel -fr vagrant
