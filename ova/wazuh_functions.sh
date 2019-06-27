install_wazuh() {
    Set_wazuh_repository()

    Install_nodejs()

    yum install wazuh-manager-$WAZUH_VERSION wazuh-api-$WAZUH_VERSION -y

    Configure_manager()

    Configure_api()

    Delete_logs()
}

Set_wazuh_repository(){
    if [ "$STATUS_PACKAGES" == "stable" ]; then
    # Wazuh production repository
        echo -e '[wazuh_repo]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=Wazuh repository \nbaseurl=https://packages.wazuh.com/3.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo

    fi

    if [ "$STATUS_PACKAGES" == "unstable" ]; then
    # Wazuh pre-release repository
        echo -e '[wazuh_repo_dev]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages-dev.wazuh.com/pre-release/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo

    fi
}

Install_nodejs(){
    curl --silent --location https://rpm.nodesource.com/setup_8.x | bash -
    yum install nodejs -y
}

Configure_manager(){
    manager_config="$DIRECTORY/etc/ossec.conf"

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
}

Configure_api(){
    # Configuring Wazuh API user and password
    cd $DIRECTORY/api/configuration/auth
    node htpasswd -b -c user foo bar

    # Enable Wazuh API SSL and configure listening port
    api_ssl_dir="${4}/api/configuration/ssl"
    openssl req -x509 -batch -nodes -days 3650 -newkey rsa:2048 -keyout ${api_ssl_dir}/server.key -out ${api_ssl_dir}/server.crt
    sed -i "s/config.https = \"no\";/config.https = \"yes\";/" ${4}/api/configuration/config.js
}

Delete_logs(){
    systemctl stop wazuh-manager
    systemctl stop wazuh-api

    find $DIRECTORY/logs -name *.log -exec : > {} \;
    rm -rf $DIRECTORY/logs/{archives,alerts,cluster,firewall,ossec}/*
    rm -rf $DIRECTORY}/stats/*

}