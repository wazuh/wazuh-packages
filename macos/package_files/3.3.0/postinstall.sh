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
DIR="/Users/0xk3vs3c/Ossec/"


# Default for all directories
chmod -R 750 ${DIR}
chown -R root:${GROUP} ${DIR}

chown -R root:wheel ${DIR}bin
chown -R root:wheel ${DIR}lib

# To the ossec queue (default for agentd to read)
chown -R ${USER}:${GROUP} ${DIR}queue/agents
chown -R ${USER}:${GROUP} ${DIR}queue/alerts
chown -R ${USER}:${GROUP} ${DIR}queue/diff
chown -R ${USER}:${GROUP} ${DIR}queue/ossec
chown -R ${USER}:${GROUP} ${DIR}queue/rids
chown -R ${USER}:${GROUP} ${DIR}queue/syscheck

chmod -R 750 ${DIR}queue/agents
chmod -R 770 ${DIR}queue/alerts
chmod -R 750 ${DIR}queue/diff
chmod -R 750 ${DIR}queue/ossec
chmod -R 750 ${DIR}queue/rids
chmod -R 750 ${DIR}queue/syscheck
chmod -R 770 ${DIR}queue/ossec

chmod 740 ${DIR}queue/diff/* > /dev/null 2>&1

# For the logging user
chown -R ${USER}:${GROUP} ${DIR}logs
chmod 770 ${DIR}logs
chmod -R 750 ${DIR}logs/*
chmod 660 ${DIR}logs/*.log
chown -R ${USER}:${GROUP} ${DIR}logs/ossec
chmod -R 750 ${DIR}logs/ossec
touch ${DIR}logs/ossec.log
chown ${USER}:${GROUP} ${DIR}logs/ossec.log
chmod 660 ${DIR}logs/ossec.log
touch ${DIR}logs/ossec.json
chown ${USER}:${GROUP} ${DIR}logs/ossec.json
chmod 660 ${DIR}logs/ossec.json

chown -R root:${GROUP} ${DIR}tmp
chmod 1750 ${DIR}tmp

chmod 770 ${DIR}etc
chown ${USER}:${GROUP} ${DIR}etc
chmod 640 ${DIR}etc/internal_options.conf
chown root:${GROUP} ${DIR}etc/internal_options.conf
chmod 640 ${DIR}etc/local_internal_options.conf > /dev/null 2>&1
chown root:${GROUP} ${DIR}etc/local_internal_options.conf > /dev/null 2>&1
chmod 640 ${DIR}etc/client.keys > /dev/null 2>&1
chown root:${GROUP} ${DIR}etc/client.keys > /dev/null 2>&1
chmod 640 ${DIR}etc/localtime
chmod 770 ${DIR}etc/shared # ossec must be able to write to it
chown -R root:${GROUP} ${DIR}etc/shared
chmod 660 ${DIR}etc/shared/*
chown -R root:${GROUP} ${DIR}etc/shared/*
chown root:${GROUP} ${DIR}etc/ossec.conf
chmod 640 ${DIR}etc/ossec.conf


chmod 700 ${DIR}.ssh

# For the /var/run
chmod -R 770 ${DIR}var/*
chown -R root:${GROUP} ${DIR}var/*

chown root:${GROUP} /etc/ossec-init.conf

if [ -n "$(cat ${DIR}etc/client.keys)" ]
then
    ${DIR}bin/ossec-control restart
fi
