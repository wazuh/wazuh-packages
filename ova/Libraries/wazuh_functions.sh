install_wazuh() {

    set_wazuh_repository
    install_nodejs
    yum install wazuh-manager-${WAZUH_VERSION} wazuh-api-${WAZUH_VERSION} -y
    configure_manager
    configure_api
    delete_logs
}

set_wazuh_repository(){

    if [ "${STATUS_PACKAGES}" = "stable" ]; then
        # Wazuh production repository
        echo -e '[wazuh_repo]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=Wazuh repository \nbaseurl=https://packages.wazuh.com/3.x/yum/\nprotect=1' | tee -a /etc/yum.repos.d/wazuh.repo
    fi

    if [ "${STATUS_PACKAGES}" = "unstable" ]; then
        # Wazuh pre-release repository
        echo -e '[wazuh_repo_dev]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-dev.wazuh.com/pre-release/yum/\nprotect=1' | tee -a /etc/yum.repos.d/wazuh.repo
    fi
}

install_nodejs(){

    curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
    yum install nodejs -y
}

configure_manager(){

    manager_config="${DIRECTORY}/etc/ossec.conf"

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
    # Remove empty ossec_config blocks
    sed -i '1b;/<ossec_config>/,/<\/ossec_config>/d' ${manager_config}

    # Configuring registration service
    sed -i '/<auth>/,/<\/auth>/d' ${manager_config}

    cat ${config_files}/ossec.conf >> ${manager_config}
    sed -i "s|INSTALLATION_DIRECTORY|${DIRECTORY}|" ${manager_config}
}

configure_api(){

    # Configuring Wazuh API user and password
    cd ${DIRECTORY}/api/configuration/auth
    node htpasswd -b -c user foo bar

    # Enable Wazuh API SSL and configure listening port
    api_ssl_dir="${DIRECTORY}/api/configuration/ssl"
    openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout ${api_ssl_dir}/server.key -out ${api_ssl_dir}/server.crt
    sed -i "s/config.https = \"no\";/config.https = \"yes\";/" ${DIRECTORY}/api/configuration/config.js
}

delete_logs(){

    systemctl stop wazuh-manager
    systemctl stop wazuh-api

    find ${DIRECTORY}/logs -type f \( -iname \*.log -o -iname \*.json \) -exec truncate -s 0 {} \;
    rm -rf ${DIRECTORY}/logs/{archives,alerts,cluster,firewall,ossec}/*
    rm -rf ${DIRECTORY}}/stats/*
}
