# Wazuh installer - indexer.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function indexer_configure() {

    common_logger -d "Configuring Wazuh indexer."
    eval "export JAVA_HOME=/usr/share/wazuh-indexer/jdk/"

    # Configure JVM options for Wazuh indexer
    ram_gb=$(free -g | awk '/^Mem:/{print $2}')
    ram=$(( ram_gb / 2 ))

    if [ "${ram}" -eq "0" ]; then
        ram=1;
    fi
    eval "sed -i "s/-Xms1g/-Xms${ram}g/" /etc/wazuh-indexer/jvm.options ${debug}"
    eval "sed -i "s/-Xmx1g/-Xmx${ram}g/" /etc/wazuh-indexer/jvm.options ${debug}"

    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig indexer/indexer_all_in_one.yml /etc/wazuh-indexer/opensearch.yml ${debug}"
    else
        eval "installCommon_getConfig indexer/indexer_unattended_distributed.yml /etc/wazuh-indexer/opensearch.yml ${debug}"
        if [ "${#indexer_node_names[@]}" -eq 1 ]; then
            pos=0
            echo "node.name: ${indxname}" >> /etc/wazuh-indexer/opensearch.yml
            echo "network.host: ${indexer_node_ips[0]}" >> /etc/wazuh-indexer/opensearch.yml
            echo "cluster.initial_master_nodes: ${indxname}" >> /etc/wazuh-indexer/opensearch.yml

            echo "plugins.security.nodes_dn:" >> /etc/wazuh-indexer/opensearch.yml
            echo '        - CN='${indxname}',OU=Wazuh,O=Wazuh,L=California,C=US' >> /etc/wazuh-indexer/opensearch.yml
        else
            echo "node.name: ${indxname}" >> /etc/wazuh-indexer/opensearch.yml
            echo "cluster.initial_master_nodes:" >> /etc/wazuh-indexer/opensearch.yml
            for i in "${indexer_node_names[@]}"; do
                echo '        - "'${i}'"' >> /etc/wazuh-indexer/opensearch.yml
            done

            echo "discovery.seed_hosts:" >> /etc/wazuh-indexer/opensearch.yml
            for i in "${indexer_node_ips[@]}"; do
                echo '        - "'${i}'"' >> /etc/wazuh-indexer/opensearch.yml
            done

            for i in "${!indexer_node_names[@]}"; do
                if [[ "${indexer_node_names[i]}" == "${indxname}" ]]; then
                    pos="${i}";
                fi
            done

            echo "network.host: ${indexer_node_ips[pos]}" >> /etc/wazuh-indexer/opensearch.yml

            echo "plugins.security.nodes_dn:" >> /etc/wazuh-indexer/opensearch.yml
            for i in "${indexer_node_names[@]}"; do
                    echo '        - CN='${i}',OU=Wazuh,O=Wazuh,L=California,C=US' >> /etc/wazuh-indexer/opensearch.yml
            done
        fi
    fi

    indexer_copyCertificates

    jv=$(java -version 2>&1 | grep -o -m1 '1.8.0' )
    if [ "$jv" == "1.8.0" ]; then
        echo "wazuh-indexer hard nproc 4096" >> /etc/security/limits.conf
        echo "wazuh-indexer soft nproc 4096" >> /etc/security/limits.conf
        echo "wazuh-indexer hard nproc 4096" >> /etc/security/limits.conf
        echo "wazuh-indexer soft nproc 4096" >> /etc/security/limits.conf
        echo -ne "\nbootstrap.system_call_filter: false" >> /etc/wazuh-indexer/opensearch.yml
    fi

    common_logger "Wazuh indexer post-install configuration finished."
}

function indexer_copyCertificates() {

    eval "rm -f ${indexer_cert_path}/* ${debug}"
    name=${indexer_node_names[pos]}

    if [ -f "${tar_file}" ]; then
        eval "mkdir ${indexer_cert_path} ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/${name}.pem  && mv ${indexer_cert_path}/wazuh-install-files/${name}.pem ${indexer_cert_path}/indexer.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/${name}-key.pem  && mv ${indexer_cert_path}/wazuh-install-files/${name}-key.pem ${indexer_cert_path}/indexer-key.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/root-ca.pem && mv ${indexer_cert_path}/wazuh-install-files/root-ca.pem ${indexer_cert_path}/ ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/admin.pem && mv ${indexer_cert_path}/wazuh-install-files/admin.pem ${indexer_cert_path}/ ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} wazuh-install-files/admin-key.pem && mv ${indexer_cert_path}/wazuh-install-files/admin-key.pem ${indexer_cert_path}/ ${debug}"
        eval "rm -rf ${indexer_cert_path}/wazuh-install-files/"
        eval "chown -R wazuh-indexer:wazuh-indexer ${indexer_cert_path} ${debug}"
        eval "chmod 750 ${indexer_cert_path} ${debug}"
        eval "chmod 600 ${indexer_cert_path}/* ${debug}"
    else
        common_logger -e "No certificates found. Could not initialize Wazuh indexer"
        exit 1;
    fi

}

function indexer_initialize() {

    common_logger "Initializing Wazuh indexer cluster security settings."
    i=0
    until curl -XGET https://${indexer_node_ips[pos]}:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null || [ "${i}" -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done
    if [ ${i} -eq 12 ]; then
        common_logger -e "Cannot initialize Wazuh indexer cluster."
        installCommon_rollBack
        exit 1
    fi

    if [ -n "${AIO}" ]; then
        eval "sudo -u wazuh-indexer JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_PATH_CONF=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig -icl -p 9300 -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig -nhnv -cacert ${indexer_cert_path}/root-ca.pem -cert ${indexer_cert_path}/admin.pem -key ${indexer_cert_path}/admin-key.pem -h 127.0.0.1 ${debug}"
    fi

    if [ "${#indexer_node_names[@]}" -eq 1 ] && [ -z "${AIO}" ]; then
        installCommon_changePasswords
    fi

    common_logger "Wazuh indexer cluster initialized."

}

function indexer_install() {

    common_logger "Starting Wazuh indexer installation."

    if [ "${sys_type}" == "yum" ]; then
        eval "yum install wazuh-indexer-${wazuh_version}-${wazuh_revision} -y ${debug}"
    elif [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install wazuh-indexer=${wazuh_version}-${wazuh_revision} ${debug}"
    elif [ "${sys_type}" == "apt-get" ]; then
        eval "DEBIAN_FRONTEND=noninteractive apt install wazuh-indexer=${wazuh_version}-${wazuh_revision} -y ${debug}"
    fi

    if [  "$?" != 0  ]; then
        common_logger -e "Wazuh indexer installation failed."
        installCommon_rollBack
        exit 1
    else
        indexerinstalled="1"
        common_logger "Wazuh indexer installation finished."
    fi

    eval "sysctl -q -w vm.max_map_count=262144 ${debug}"

}

function indexer_startCluster() {

    eval "wazuh_indexer_ip=( $(cat /etc/wazuh-indexer/opensearch.yml | grep network.host | sed 's/network.host:\s//') )"
    eval "sudo -u wazuh-indexer JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_PATH_CONF=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -p 9300 -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/ -icl -nhnv -cacert /etc/wazuh-indexer/certs/root-ca.pem -cert /etc/wazuh-indexer/certs/admin.pem -key /etc/wazuh-indexer/certs/admin-key.pem -h ${wazuh_indexer_ip} ${debug}"
    if [  "$?" != 0  ]; then
        common_logger -e "The Wazuh indexer cluster security configuration could not be initialized."
        installCommon_rollBack
        exit 1
    else
        common_logger "Wazuh indexer cluster security configuration initialized."
    fi
    eval "curl --silent ${filebeat_wazuh_template} | curl -X PUT 'https://${indexer_node_ips[pos]}:9200/_template/wazuh' -H 'Content-Type: application/json' -d @- -uadmin:admin -k --silent ${debug}"
    if [  "$?" != 0  ]; then
        common_logger -e "The wazuh-alerts template could not be inserted into the Wazuh indexer cluster."
        installCommon_rollBack
        exit 1
    else
        common_logger -d "Inserted wazuh-alerts template into the Wazuh indexer cluster."
    fi

}