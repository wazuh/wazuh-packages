#!/bin/bash

# Set debug mode
[[ ${DEBUG} = "yes" ]] && set -ex || set -e

# Edit system config
systemConfig() {

  # Upgrade system packages
  echo "Upgrading the system. This may take a while ..."
  yum upgrade -y > /dev/null 2>&1

  # Disable kernel message and edit background
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

  # Grant sudo privileges to user
  gpasswd -a wazuh wheel

  # Set Hostname
  hostname wazuhmanager

  # Ssh config
  sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config

  # Edit custom welcome messages
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

  # Add Kibana custom user wazuh
  PATTERN="eval \"rm \/etc\/elasticsearch\/e"
  HASH="\\\$2y\\\$12\\\$qCvlv3y4\\\.i8nX6wUZOepROVhTWI36H8nH2gxwShHcpIzf0yV1J30K"  # password: wazuh
  FILE_PATH="\/usr\/share\/elasticsearch\/plugins\/opendistro_security\/securityconfig"
  sed -i "s/${PATTERN}/sed -i \'\/admin:\/ {N; s\/admin.*\/wazuh:\\\n  hash: \"${HASH}\"\/g}\' ${FILE_PATH}\/internal_users\.yml\n        ${PATTERN}/g" ${INSTALLER}
  
  # Set backend_role for wazuh user with all_access
  sed -i "s/${PATTERN}/sed -i \'s\/\"admin\"\/\"wazuh\"\/g\' ${FILE_PATH}\/roles_mapping\.yml\n        ${PATTERN}/g" ${INSTALLER}
  sed -i "s/${PATTERN}/sed -i \'s\/\"admin\"\/\"wazuh\"\/g\' ${FILE_PATH}\/internal_users\.yml\n        ${PATTERN}/g" ${INSTALLER}

  # Change user:password in curls
  sed -i "s/admin:admin/wazuh:wazuh/g" ${INSTALLER}

  # Change user:password in filebeat.yml
  PATTERN="eval \"curl -so \/etc\/filebeat\/wazuh-template"
  sed -i "s/${PATTERN}/sed -i \"s\/admin\/wazuh\/g\" \/etc\/filebeat\/filebeat\.yml\n        ${PATTERN}/g" ${INSTALLER}

  # Edit kibana plugin versions
  sed -i "s/wazuh\_kibana\-[0-9\.]*_[0-9\.]*\-1\.zip/wazuh_kibana-${WAZUH_VERSION}_${ELK_VERSION}-${UI_REVISION}.zip/g" ${INSTALLER}

  # Disable start of wazuh-manager
  sed -i "s/startService \"wazuh-manager\"/\#startService \"wazuh-manager\"/g" ${INSTALLER}

}

# Edit wazuh installation
postInstall() {

  # Custom Login Page
  # Edit window title
  sed -i "s/null, \"Elastic\"/null, \"Wazuh\"/g" /usr/share/kibana/src/core/server/rendering/views/template.js

  # Download custom files (background, logo and template)
  curl -so ${CUSTOM_PATH}/custom_welcome.tar.gz https://wazuh-demo.s3-us-west-1.amazonaws.com/custom_welcome_opendistro_docker.tar.gz
  tar -xf ${CUSTOM_PATH}/custom_welcome.tar.gz -C ${CUSTOM_PATH}

  # Copy necesaries files
  cp ${CUSTOM_PATH}/custom_welcome/wazuh_logo_circle.svg /usr/share/kibana/src/core/server/core_app/assets/
  cp ${CUSTOM_PATH}/custom_welcome/wazuh_wazuh_bg.svg /usr/share/kibana/src/core/server/core_app/assets/
  cp ${CUSTOM_PATH}/custom_welcome/template.js.hbs /usr/share/kibana/src/legacy/ui/ui_render/bootstrap/template.js.hbs

  # Add custom configuration to css
  less ${CUSTOM_PATH}/customWelcomeKibana.css >> /usr/share/kibana/src/core/server/core_app/assets/legacy_light_theme.css

}

clean() {

  # Remove installer
  rm ${INSTALLER}

  # Clean cache
  yum clean all

  # Remove demo script and default centos configuration install
  rm /securityadmin_demo.sh
  rm /root/anaconda-ks.cfg
  rm /root/original-ks.cfg

}
