#!/bin/bash

[[ ${DEBUG} = "yes" ]] && set -ex || set -e

# Edit system configuration
systemConfig() {

  echo "Upgrading the system. This may take a while ..."
  yum upgrade -y > /dev/null 2>&1

  # Disable kernel messages and edit background
  mv ${CUSTOM_PATH}/grub/wazuh.png /boot/grub2/
  mv ${CUSTOM_PATH}/grub/grub /etc/default/
  grub2-mkconfig -o /boot/grub2/grub.cfg > /dev/null 2>&1

  # Set dinamic ram of vm
  mv ${CUSTOM_PATH}/automatic_set_ram.sh /etc/
  chmod +x "/etc/automatic_set_ram.sh"
  echo "@reboot . /etc/automatic_set_ram.sh" >> cron
  crontab cron
  rm cron

  # Change root password (root:wazuh)
  sed -i "s/root:.*:/root:\$1\$pNjjEA7K\$USjdNwjfh7A\.vHCf8suK41::0:99999:7:::/g" /etc/shadow 

  # Add user wazuh (wazuh:wazuh)
  adduser wazuh
  sed -i "s/wazuh:!!/wazuh:\$1\$pNjjEA7K\$USjdNwjfh7A\.vHCf8suK41/g" /etc/shadow 

  gpasswd -a wazuh wheel
  hostname wazuh-manager

  # Ssh configuration
  sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config

  # Edit system custom welcome messages
  sh ${CUSTOM_PATH}/messages.sh ${DEBUG} ${WAZUH_VERSION}
}

# Edit unnatended installer
preInstall() {

  # Set debug mode
  if [ "${DEBUG}" == "yes" ]; then
    sed -i "s/\#\!\/bin\/bash/\#\!\/bin\/bash\nset -x/g" ${INSTALLER}
  fi

  # Get currents version values of installer
  CURRENT_W=$(less ${INSTALLER} | grep "WAZUH_VER=")
  CURRENT_O=$(less ${INSTALLER} | grep "OD_VER=")
  CURRENT_E=$(less ${INSTALLER} | grep "ELK_VER=")

  # Change wazuh and documentation repository branch
  sed -i "s/uh\/[0-9]\+\.[0-9]\+\/ex/uh\/${BRANCH}\/ex/g" ${INSTALLER}
  sed -i "s/on\/[0-9]\+\.[0-9]\+\/re/on\/${BRANCHDOC}\/re/g" ${INSTALLER}

  # Change versions
  sed -i "s/${CURRENT_W}/WAZUH_VER=\"${WAZUH_VERSION}\"/g" ${INSTALLER}
  sed -i "s/${CURRENT_O}/OD_VER=\"${OPENDISTRO_VERSION}\"/g" ${INSTALLER}
  sed -i "s/${CURRENT_E}/ELK_VER=\"${ELK_VERSION}\"/g" ${INSTALLER}

  # Change repository if dev is specified
  if [ "${PACKAGES_REPOSITORY}" = "dev" ]; then
      sed -i "s/\[wazuh\]/\[wazuh_pre_release\]/g" ${INSTALLER}
      sed -i "s/ngpgkey\=https\:\/\/packages\.wazuh\.com/ngpgkey\=https\:\/\/packages\-dev\.wazuh\.com/g" ${INSTALLER}
      sed -i "s/baseurl\=https\:\/\/packages\.wazuh\.com\/4\.x/baseurl\=https\:\/\/packages\-dev\.wazuh\.com\/pre\-release/g" ${INSTALLER}
      sed -i "s/https\:\/\/packages\.wazuh\.com\/4\.x\/ui\/kibana/https\:\/\/packages\-dev\.wazuh\.com\/pre\-release\/ui\/kibana/g" ${INSTALLER}
      sed -i "s/wazuh_kibana-[0-9\.]\+_[0-9\.]\+/wazuh_kibana-${WAZUH_VERSION}_${ELK_VERSION}/g" ${INSTALLER}
  fi

  # Edit kibana plugin versions
  sed -i "s/wazuh\_kibana\-[0-9\.]*_[0-9\.]*\-1\.zip/wazuh_kibana-${WAZUH_VERSION}_${ELK_VERSION}-${UI_REVISION}.zip/g" ${INSTALLER}
  
  # Disable start of wazuh-manager
  sed -i "s/startService \"wazuh-manager\"/\#startService \"wazuh-manager\"/g" ${INSTALLER}

  # Disable passwords change
  sed -i "s/wazuhpass=/#wazuhpass=/g" ${INSTALLER}
  sed -i "s/changePasswords$/#changePasswords\nwazuhpass=wazuh/g" ${INSTALLER}
  sed -i "s/ra=/#ra=/g" ${INSTALLER}
  
}

# Edit wazuh installation
postInstall() {

  # Edit window title
  sed -i "s/null, \"Elastic\"/null, \"Wazuh\"/g" /usr/share/kibana/src/core/server/rendering/views/template.js

  curl -so ${CUSTOM_PATH}/custom_welcome.tar.gz https://wazuh-demo.s3-us-west-1.amazonaws.com/custom_welcome_opendistro_docker.tar.gz
  tar -xf ${CUSTOM_PATH}/custom_welcome.tar.gz -C ${CUSTOM_PATH}
  cp ${CUSTOM_PATH}/custom_welcome/wazuh_logo_circle.svg /usr/share/kibana/src/core/server/core_app/assets/
  cp ${CUSTOM_PATH}/custom_welcome/wazuh_wazuh_bg.svg /usr/share/kibana/src/core/server/core_app/assets/
  cp ${CUSTOM_PATH}/custom_welcome/template.js.hbs /usr/share/kibana/src/legacy/ui/ui_render/bootstrap/template.js.hbs

  # Add custom css in kibana
  less ${CUSTOM_PATH}/customWelcomeKibana.css >> /usr/share/kibana/src/core/server/core_app/assets/legacy_light_theme.css

}

clean() {

  rm ${INSTALLER}
  rm /securityadmin_demo.sh
  yum clean all

}
