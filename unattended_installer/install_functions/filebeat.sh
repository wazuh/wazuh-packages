# Wazuh installer - filebeat.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function filebeat_configure(){

    common_logger -d "Configuring Filebeat."

    if [ -z "${offline_install}" ]; then
        eval "common_curl -sSo /etc/filebeat/wazuh-template.json ${filebeat_wazuh_template} --max-time 300 --retry 5 --retry-delay 5 --fail"
        if [ ! -f "/etc/filebeat/wazuh-template.json" ]; then
            common_logger -e "Error downloading wazuh-template.json file."
            installCommon_rollBack
            exit 1
        fi
        common_logger -d "Filebeat template was download successfully."

        eval "(common_curl -sS ${filebeat_wazuh_module} --max-time 300 --retry 5 --retry-delay 5 --fail | tar -xvz -C /usr/share/filebeat/module) ${debug}"
        if [ ! -d "/usr/share/filebeat/module" ]; then
            common_logger -e "Error downloading wazuh filebeat module."
            installCommon_rollBack
            exit 1
        fi
        common_logger -d "Filebeat module was downloaded successfully."
    else
        eval "cp ${offline_files_path}/wazuh-template.json /etc/filebeat/wazuh-template.json ${debug}"
        eval "tar -xvzf ${offline_files_path}/wazuh-filebeat-*.tar.gz -C /usr/share/filebeat/module ${debug}"
    fi

    eval "chmod go+r /etc/filebeat/wazuh-template.json ${debug}"
    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig filebeat/filebeat_unattended.yml /etc/filebeat/filebeat.yml ${debug}"
    else
        eval "installCommon_getConfig filebeat/filebeat_distributed.yml /etc/filebeat/filebeat.yml ${debug}"
        if [ ${#indexer_node_names[@]} -eq 1 ]; then
            echo -e "\noutput.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
            echo "  - ${indexer_node_ips[0]}:9200" >> /etc/filebeat/filebeat.yml
        else
            echo -e "\noutput.elasticsearch.hosts:" >> /etc/filebeat/filebeat.yml
            for i in "${indexer_node_ips[@]}"; do
                echo "  - ${i}:9200" >> /etc/filebeat/filebeat.yml
            done
        fi
    fi

    eval "mkdir /etc/filebeat/certs ${debug}"
    filebeat_copyCertificates

    eval "filebeat keystore create ${debug}"
    eval "(echo admin | filebeat keystore add username --force --stdin)" "${debug}"
    eval "(echo admin | filebeat keystore add password --force --stdin)" "${debug}"

    common_logger "Filebeat post-install configuration finished."
}

function filebeat_copyCertificates() {

    common_logger -d "Copying Filebeat certificates."
    if [ -f "${tar_file}" ]; then
        if [ -n "${AIO}" ]; then
            if ! tar -tvf "${tar_file}" | grep -q "${server_node_names[0]}" ; then
                common_logger -e "Tar file does not contain certificate for the node ${server_node_names[0]}."
                installCommon_rollBack
                exit 1
            fi
            eval "sed -i s/filebeat.pem/${server_node_names[0]}.pem/ /etc/filebeat/filebeat.yml ${debug}"
            eval "sed -i s/filebeat-key.pem/${server_node_names[0]}-key.pem/ /etc/filebeat/filebeat.yml ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} --wildcards wazuh-install-files/${server_node_names[0]}.pem --strip-components 1 ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} --wildcards wazuh-install-files/${server_node_names[0]}-key.pem --strip-components 1 ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/root-ca.pem --strip-components 1 ${debug}"
            eval "rm -rf ${filebeat_cert_path}/wazuh-install-files/ ${debug}"
        else
            if ! tar -tvf "${tar_file}" | grep -q "${winame}" ; then
                common_logger -e "Tar file does not contain certificate for the node ${winame}."
                installCommon_rollBack
                exit 1
            fi
            eval "sed -i s/filebeat.pem/${winame}.pem/ /etc/filebeat/filebeat.yml ${debug}"
            eval "sed -i s/filebeat-key.pem/${winame}-key.pem/ /etc/filebeat/filebeat.yml ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/${winame}.pem --strip-components 1 ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/${winame}-key.pem --strip-components 1 ${debug}"
            eval "tar -xf ${tar_file} -C ${filebeat_cert_path} wazuh-install-files/root-ca.pem --strip-components 1 ${debug}"
            eval "rm -rf ${filebeat_cert_path}/wazuh-install-files/ ${debug}"
        fi
        eval "chmod 500 ${filebeat_cert_path} ${debug}"
        eval "chmod 400 ${filebeat_cert_path}/* ${debug}"
        eval "chown root:root ${filebeat_cert_path}/* ${debug}"
    else
        common_logger -e "No certificates found. Could not initialize Filebeat"
        installCommon_rollBack
        exit 1
    fi

}

function filebeat_install() {

    common_logger "Starting Filebeat installation."
    if [ "${sys_type}" == "yum" ]; then
        installCommon_yumInstall "filebeat" "${filebeat_version}"
    elif [ "${sys_type}" == "apt-get" ]; then
        installCommon_aptInstall "filebeat" "${filebeat_version}"
    fi

    install_result="${PIPESTATUS[0]}"
    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${filebeat_installed}" ]; then
        common_logger -e "Filebeat installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Filebeat installation finished."
    fi

}
