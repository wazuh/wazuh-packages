#! /bin/bash
# By Spransy, Derek" <DSPRANS () emory ! edu> and Charlie Scott
# Modified by Santiago Bassett (http://www.wazuh.com) - Feb 2016
# alterations by bil hays 2013
# -Switched to bash
# -Added some sanity checks
# -Added routine to find the first 3 contiguous UIDs above 100,
#  starting at 600 puts this in user space
# -Added lines to append the ossec users to the group ossec
#  so the the list GroupMembership works properly

GROUP="ossec"
USER="ossec"
subdirs="logs bin queue queue/ossec queue/alerts queue/syscheck queue/rids queue/diff tmp var var/run etc etc/shared active-response active-response/bin agentless .ssh"
DIR="/Users/0xk3vs3c/Ossec/"


# Default for all directories
chmod -R 550 ${DIR}
chown -R root:${GROUP} ${DIR}

# To the ossec queue (default for agentd to read)
chown -R ${USER}:${GROUP} ${DIR}/queue/ossec
chmod -R 770 ${DIR}/queue/ossec

# For the logging user
chown -R ${USER}:${GROUP} ${DIR}/logs
chmod -R 750 ${DIR}/logs
chown -R ${USER}:${GROUP} ${DIR}/logs/ossec
chmod -R 750 ${DIR}/logs/ossec
chmod -R 775 ${DIR}/queue/rids
touch ${DIR}/logs/ossec.log
chown ${USER}:${GROUP} ${DIR}/logs/ossec.log
chmod 664 ${DIR}/logs/ossec.log
touch ${DIR}/logs/ossec.json
chown ${USER}:${GROUP} ${DIR}/logs/ossec.json
chmod 664 ${DIR}/logs/ossec.json

chown -R ${USER}:${GROUP} ${DIR}/queue/diff
chmod -R 750 ${DIR}/queue/diff
chmod 740 ${DIR}/queue/diff/* > /dev/null 2>&1

chown -R root:${GROUP} ${DIR}/tmp
chmod 1550 ${DIR}/tmp



# For the etc dir
chmod 550 ${DIR}/etc
chown -R root:${GROUP} ${DIR}/etc

chown root:${GROUP} ${DIR}/etc/internal_options.conf
chown root:${GROUP} ${DIR}/etc/local_internal_options.conf > /dev/null 2>&1
chown root:${GROUP} ${DIR}/etc/client.keys > /dev/null 2>&1
chown root:${GROUP} ${DIR}/agentless/*
chown ${USER}:${GROUP} ${DIR}/.ssh
chown -R root:${GROUP} ${DIR}/etc/shared

chmod 550 ${DIR}/etc
chmod 640 ${DIR}/etc/internal_options.conf
chmod 440 ${DIR}/etc/local_internal_options.conf > /dev/null 2>&1
chmod 440 ${DIR}/etc/client.keys > /dev/null 2>&1
chmod -R 770 ${DIR}/etc/shared # ossec must be able to write to it
chmod 550 ${DIR}/agentless/*
chmod 700 ${DIR}/.ssh

# For the /var/run
chmod 770 ${DIR}/var/run
chown root:${GROUP} ${DIR}/var/run

chown root:${GROUP} ${DIR}/bin/util.sh
chmod +x ${DIR}/bin/util.sh

chmod 755 ${DIR}/active-response/bin/*
chown root:${GROUP} ${DIR}/active-response/bin/*

chown root:${GROUP} ${DIR}/bin/*
chmod 550 ${DIR}/bin/*

chown root:${GROUP} ${DIR}/etc/ossec.conf
chmod 640 ${DIR}/etc/ossec.conf

chown root:${GROUP} /etc/ossec-init.conf

if [ -n "$(cat ${DIR}/etc/client.keys)" ]
then
    ${DIR}/bin/ossec-control restart
fi
