#!/bin/sh

# install wazuh dependencies & some important packages

PATH=$PATH:/usr/sfw/bin:/opt/csw/bin
yes | /usr/sbin/pkgadd -d http://get.opencsw.org/now all
/opt/csw/bin/pkgutil -U

#Download and install tools
pkgutil -y -i git
pkgutil -y -i gmake
pkgutil -y -i automake
pkgutil -y -i autoconf
pkgutil -y -i libtool
pkgutil -y -i wget
pkgutil -y -i curl
pkgutil -y -i gcc5core
pkgutil -y -i perl
pkgutil -y -i sudo
pkgutil -y -i git
rm /usr/bin/perl
mv /opt/csw/bin/perl5.10.1 /usr/bin/
mv /usr/bin/perl5.10.1 /usr/bin/perl


# Adds vagrant user to the sudoers as a user that can run any command without being asked to introduce the password
# Read more: https://www.vagrantup.com/docs/boxes/base.html
echo 'vagrant ALL=(ALL) NOPASSWD: ALL' >> /etc/opt/csw/sudoers



# setup the vagrant key
# you can replace this key-pair with your own generated ssh key-pair
echo "Setting the vagrant ssh pub key"
mkdir /export/home/vagrant/.ssh
chmod 750 /export/home/vagrant/.ssh
touch /export/home/vagrant/.ssh/authorized_keys
if [ -f /usr/sfw/bin/wget ] ; then
  /usr/sfw/bin/wget --no-check-certificate https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant.pub -O /export/home/vagrant/.ssh/authorized_keys
else
  wget --no-check-certificate https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant.pub -O /export/home/vagrant/.ssh/authorized_keys
fi
chmod 600 /export/home/vagrant/.ssh/authorized_keys
chown -R vagrant:staff /export/home/vagrant/.ssh

ln -fs /opt/csw/bin/sudo /usr/bin/sudo
ln -fs /opt/csw/bin/sudo /bin/sudo


echo "Disabling sendmail and asr-norify"
# disable the very annoying sendmail
/usr/sbin/svcadm disable sendmail
/usr/sbin/svcadm disable asr-notify

echo "Clearing log files and zeroing disk, this might take a while"
cp /dev/null /var/adm/messages
cp /dev/null /var/log/syslog
cp /dev/null /var/adm/wtmpx
cp /dev/null /var/adm/utmpx
dd if=/dev/zero of=/EMPTY bs=1024 | true
rm -f /EMPTY

echo "Post-install done"
