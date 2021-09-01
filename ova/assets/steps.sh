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

  # AWS instance has this enabled
  sed -i "s/PermitRootLogin yes/#PermitRootLogin yes/g" /etc/ssh/sshd_config

  # Ssh configuration
  sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config

  # Edit system custom welcome messages
  sh ${CUSTOM_PATH}/messages.sh ${DEBUG} ${WAZUH_VERSION}

}

# Edit unattended installer
preInstall() {

  # Set debug mode
  if [ "${DEBUG}" == "yes" ]; then
    sed -i "s/\#\!\/bin\/bash/\#\!\/bin\/bash\nset -x/g" ${INSTALLER}
  fi

  # Remove debug in unattended script
  sed -i "s/\${debug}//g" ${INSTALLER}

  # Change repository if dev is specified
  if [ "${PACKAGES_REPOSITORY}" = "dev" ]; then
    sed -i "s/packages\.wazuh\.com/packages-dev\.wazuh\.com/g" ${INSTALLER} 
    sed -i "s/packages-dev\.wazuh\.com\/4\.x/packages-dev\.wazuh\.com\/pre-release/g" ${INSTALLER} 
  fi

  # Remove kibana admin user
  PATTERN="eval \"rm \/etc\/elasticsearch\/e"
  FILE_PATH="\/usr\/share\/elasticsearch\/plugins\/opendistro_security\/securityconfig"
  sed -i "s/${PATTERN}/sed -i \'\/^admin:\/,\/admin user\\\\\"\/d\' ${FILE_PATH}\/internal_users\.yml\n        ${PATTERN}/g" ${INSTALLER}
 
  # Change user:password in curls
  sed -i "s/admin:admin/wazuh:wazuh/g" ${INSTALLER}

  # Replace admin/admin for wazuh/wazuh in filebeat.yml
  PATTERN="eval \"curl -so \/etc\/filebeat\/wazuh-template"
  sed -i "s/${PATTERN}/sed -i \"s\/admin\/wazuh\/g\" \/etc\/filebeat\/filebeat\.yml\n        ${PATTERN}/g" ${INSTALLER}

  # Disable start of wazuh-manager
  sed -i "s/startService \"wazuh-manager\"/\#startService \"wazuh-manager\"/g" ${INSTALLER}

  # Disable passwords change
  sed -i "s/wazuhpass=/#wazuhpass=/g" ${INSTALLER}
  sed -i "s/changePasswords$/#changePasswords\nwazuhpass=\"wazuh\"/g" ${INSTALLER}
  sed -i "s/ra=/#ra=/g" ${INSTALLER}

  # Revert url to packages.wazuh.com to get filebeat gz
  sed -i "s/'\${repobaseurl}'\/filebeat/https:\/\/packages.wazuh.com\/4.x\/filebeat/g" ${INSTALLER}

  # Change wazuh-packages branch
  sed -i "s/WAZUH_MAJOR=\"4.2\"/WAZUH_MAJOR=\"${PACKAGES_BRANCH}\"/g" ${INSTALLER}

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
