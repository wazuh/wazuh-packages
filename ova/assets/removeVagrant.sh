#!/bin/bash

# Remove vagrant user
userdel -rf vagrant

# Remove vagrant from system files
sed -i "/vagrant/d" /etc/group-
sed -i "/vagrant/d" /etc/gshadow-
sed -i "/vagrant/d" /etc/passwd-
sed -i "/vagrant/d" /etc/shadow-
sed -i "/\\\/d" /etc/pam.d/su
sed -i "/vagrant/d" /etc/pam.d/su
rm /etc/sudoers.d/vagrant

# Remove this script
rm /home/wazuh/removeVagrant.sh

# Remove service 
rm /etc/systemd/system/removeVagrant.service
rm /etc/systemd/system/multi-user.target.wants/removeVagrant.service
systemctl daemon-reload
