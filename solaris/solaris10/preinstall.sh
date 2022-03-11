#!/bin/sh
# preinstall script for wazuh-agent
# Wazuh, Inc 2015-2022

if [ ! -f /etc/ossec-init.conf ]; then
	DIR="/var/ossec"
	ls -la /var/ossec > /dev/null 2>&1
    if [ -d  /var/ossec ]; then
		#upgrade
        type=upgrade

	else
		#clean installation
        type=install
    fi

else
	#upgrade
	DIR=`cat $INSTALLATION_FILE | grep DIRECTORY | cut -d'=' -f2 | cut -d'"' -f2`
	type=upgrade

fi

USER="wazuh"
GROUP="wazuh"
OSSEC_HIDS_TMP_DIR="/tmp/wazuh-agent"
OSMYSHELL="/sbin/nologin"

# environment configuration
if [ ! -d ${OSSEC_HIDS_TMP_DIR} ]; then
  mkdir ${OSSEC_HIDS_TMP_DIR}
fi

if [ ! -f ${OSMYSHELL} ]; then
  if [ -f "/bin/false" ]; then
    OSMYSHELL="/bin/false"
  fi
fi

getent group | grep "^wazuh"
if [ "$?" -eq 1 ]; then
  groupadd ${GROUP}
fi

getent passwd | grep "^wazuh"
if [ "$?" -eq 1 ]; then
  useradd -d ${DIR} -s ${OSMYSHELL} -g ${GROUP} ${USER} > /dev/null 2>&1
fi

case $type in
    upgrade)

    if [ -d "$DIR" ]; then
        if [ -f ${DIR}/etc/ossec.conf ]; then
            cp -p ${DIR}/etc/ossec.conf ${OSSEC_HIDS_TMP_DIR}/ossec.conf
        fi

    ;;

    install)

    ;;

    *)

    ;;

esac

exit 0
