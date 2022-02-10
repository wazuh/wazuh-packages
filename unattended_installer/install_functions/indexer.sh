# Wazuh installer - indexer.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

readonly i_certs_path="/etc/wazuh-indexer/certs/"

function indexer_configure() {

    logger -d "Configuring Wazuh indexer."
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
        eval "common_getConfig indexer/indexer_all_in_one.yml /etc/wazuh-indexer/opensearch.yml ${debug}"
    else
        eval "common_getConfig indexer/indexer_unattended_distributed.yml /etc/wazuh-indexer/opensearch.yml ${debug}"
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

    logger "Wazuh indexer post-install configuration finished."
}

function indexer_copyCertificates() {

    eval "rm -f ${i_certs_path}/* ${debug}"
    name=${indexer_node_names[pos]}

    if [ -f "${tar_file}" ]; then
        eval "tar -xf ${tar_file} -C ${i_certs_path} ./${name}.pem  && mv ${i_certs_path}${name}.pem ${i_certs_path}indexer.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${i_certs_path} ./${name}-key.pem  && mv ${i_certs_path}${name}-key.pem ${i_certs_path}indexer-key.pem ${debug}"
        eval "tar -xf ${tar_file} -C ${i_certs_path} ./root-ca.pem  ${debug}"
        eval "tar -xf ${tar_file} -C ${i_certs_path} ./admin.pem  ${debug}"
        eval "tar -xf ${tar_file} -C ${i_certs_path} ./admin-key.pem  ${debug}"
    else
        logger -e "No certificates found. Could not initialize Wazuh indexer"
        exit 1;
    fi

}

function indexer_initialize() {

    logger "Starting Wazuh indexer cluster."
    i=0
    until curl -XGET https://${indexer_node_ips[pos]}:9700/ -uadmin:admin -k --max-time 120 --silent --output /dev/null || [ "${i}" -eq 12 ]; do
        sleep 10
        i=$((i+1))
    done
    if [ ${i} -eq 12 ]; then
        logger -e "Cannot start Wazuh indexer cluster."
        common_rollBack
        exit 1
    fi

    if [ -n "${AIO}" ]; then
        eval "sudo -u wazuh-indexer JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_PATH_CONF=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig -icl -p 9800 -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig -nhnv -cacert ${i_certs_path}root-ca.pem -cert ${i_certs_path}admin.pem -key ${i_certs_path}admin-key.pem -h 127.0.0.1 ${debug}"
    fi

    if [ "${#indexer_node_names[@]}" -eq 1 ] && [ -z "${AIO}" ]; then
        common_changePasswords
    fi

    logger "Wazuh indexer cluster started."

}

function indexer_install() {

    logger "Starting Wazuh indexer installation."

    if [ "${sys_type}" == "yum" ]; then
        eval "yum install wazuh-indexer-${wazuh_version}-${wazuh_revision} -y ${debug}"
    elif [ "${sys_type}" == "zypper" ]; then
        eval "zypper -n install wazuh-indexer=${wazuh_version}-${wazuh_revision} ${debug}"
    elif [ "${sys_type}" == "apt-get" ]; then
        eval "apt install wazuh-indexer=${wazuh_version}-${wazuh_revision} -y ${debug}"
    fi

    if [  "$?" != 0  ]; then
        logger -e "Wazuh indexer installation failed."
        indexerchinstalled="indexer"
        common_rollBack
        exit 1
    else
        indexerchinstalled="1"
        logger "Wazuh indexer installation finished."
    fi

    eval "sysctl -q -w vm.max_map_count=262144 ${debug}"

}

function indexer_startCluster() {

    eval "wazuh_indexer_ip=( $(cat /etc/wazuh-indexer/opensearch.yml | grep network.host | sed 's/network.host:\s//') )"
    eval "sudo -u wazuh-indexer JAVA_HOME=/usr/share/wazuh-indexer/jdk/ OPENSEARCH_PATH_CONF=/etc/wazuh-indexer /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -p 9800 -cd /usr/share/wazuh-indexer/plugins/opensearch-security/securityconfig/ -icl -nhnv -cacert /etc/wazuh-indexer/certs/root-ca.pem -cert /etc/wazuh-indexer/certs/admin.pem -key /etc/wazuh-indexer/certs/admin-key.pem -h ${wazuh_indexer_ip} ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "The Wazuh indexer cluster security configuration could not be initialized."
        common_rollBack
        exit 1
    else
        logger "Wazuh indexer cluster security configuration initialized."
    fi
    eval "curl --silent ${filebeat_wazuh_template} | curl -X PUT 'https://${indexer_node_ips[pos]}:9700/_template/wazuh' -H 'Content-Type: application/json' -d @- -uadmin:admin -k --silent ${debug}"
    if [  "$?" != 0  ]; then
        logger -e "The wazuh-alerts template could not be inserted into the Wazuh indexer cluster."
        common_rollBack
        exit 1
    else
        logger -d "The wazuh-alerts template inserted into the Wazuh indexer cluster."
    fi

}

function indexer_uninstall() {

    logger "Starting Wazuh indexer uninstall."

    if [[ -n "${indexerchinstalled}" ]]; then
        logger -w "Removing Wazuh packages."
        if [ "${sys_type}" == "yum" ]; then
            eval "yum remove wazuh-indexer -y ${debug}"
        elif [ "${sys_type}" == "zypper" ]; then
            eval "zypper -n remove wazuh-indexer ${debug}"
        elif [ "${sys_type}" == "apt-get" ]; then
            eval "apt remove --purge ^wazuh-indexer -y ${debug}"
        fi
    fi

    if [[ -n "${indexer_remaining_files}" ]]; then
        logger -w "Removing Wazuh indexer files."

        elements_to_remove=(    "/etc/systemd/system/multi-user.target.wants/elasticsearch.service"
                                "/etc/systemd/system/kibana.service"
                                "/var/lib/wazuh-indexer/"
                                "/usr/share/wazuh-indexer"
                                "/etc/wazuh-indexer/"
                                "/var/log/elasticsearch/"
                                "/var/log/wazuh-indexer/"
                                "/etc/systemd/system/opensearch.service.wants/"
                                "/securityadmin_demo.sh"
                                "/etc/systemd/system/multi-user.target.wants/opensearch.service"
                                "/lib/firewalld/services/opensearch.xml"
                                "${base_path}/search-guard-tlstool*" )

        eval "rm -rf ${elements_to_remove[*]} ${debug}"
    fi

}