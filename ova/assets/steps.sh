#!/bin/bash

[[ ${DEBUG} = "yes" ]] && set -ex || set -e

# Edit system configuration
systemConfig() {

  echo "Upgrading the system. This may take a while ..."
  #yum upgrade -y > /dev/null 2>&1

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

  # Add custom user ($1$pNjjEA7K$USjdNwjfh7A.vHCf8suK41 -> wazuh)
  adduser ${SYSTEM_USER}
  sed -i "s/${SYSTEM_USER}:!!/${SYSTEM_USER}:\$1\$pNjjEA7K\$USjdNwjfh7A\.vHCf8suK41/g" /etc/shadow 

  gpasswd -a ${SYSTEM_USER} wheel
  hostname ${HOSTNAME}

  # AWS instance has this enabled
  sed -i "s/PermitRootLogin yes/#PermitRootLogin yes/g" /etc/ssh/sshd_config

  # SSH configuration
  sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
  echo "PermitRootLogin no" >> /etc/ssh/sshd_config

  # Edit system custom welcome messages
  bash ${CUSTOM_PATH}/messages.sh ${DEBUG} ${WAZUH_VERSION} ${SYSTEM_USER}

}

# Edit unattended installer
preInstall() {

  # Disable passwords change
  sed -i "s/changePasswords/#changePasswords/g" ${RESOURCES_PATH}/${INSTALLER}

}

clean() {

  rm -f /securityadmin_demo.sh
  yum clean all

}
