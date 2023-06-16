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
GROUP="wazuh"
USER="wazuh"
DIR="/Library/Ossec"
INSTALLATION_SCRIPTS_DIR="${DIR}/packages_files/agent_installation_scripts"
SCA_BASE_DIR="${INSTALLATION_SCRIPTS_DIR}/sca"

upgrade="true"
touch ${DIR}/POSTUPGRADE

if [ -f "${DIR}/WAZUH_RESTART" ]; then
  restart="true"
fi

if [ -f "${DIR}/WAZUH_RESTART" ]; then
  rm -f ${DIR}/WAZUH_RESTART
fi

if [ -n "${upgrade}" ]; then
    rm -rf ${DIR}/etc/{ossec.conf,client.keys,local_internal_options.conf,shared}
    cp -rf ${DIR}/config_files/{ossec.conf,client.keys,local_internal_options.conf,shared} ${DIR}/etc/
    rm -rf ${DIR}/config_files/
fi

. ${INSTALLATION_SCRIPTS_DIR}/src/init/dist-detect.sh


if [ -z "${upgrade}" ]; then
    ${INSTALLATION_SCRIPTS_DIR}/gen_ossec.sh conf agent ${DIST_NAME} ${DIST_VER}.${DIST_SUBVER} ${DIR} > ${DIR}/etc/ossec.conf
    chown root:wazuh ${DIR}/etc/ossec.conf
    chmod 0640 ${DIR}/etc/ossec.conf
fi

SCA_DIR="${DIST_NAME}/${DIST_VER}"
mkdir -p ${DIR}/ruleset/sca

SCA_TMP_DIR="${SCA_BASE_DIR}/${SCA_DIR}"

# Install the configuration files needed for this hosts
if [ -r "${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/${DIST_SUBVER}/sca.files" ]; then
    SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/${DIST_SUBVER}"
elif [ -r "${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}/sca.files" ]; then
    SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}/${DIST_VER}"
elif [ -r "${SCA_BASE_DIR}/${DIST_NAME}/sca.files" ]; then
    SCA_TMP_DIR="${SCA_BASE_DIR}/${DIST_NAME}"
else
    SCA_TMP_DIR="${SCA_BASE_DIR}/generic"
fi

SCA_TMP_FILE="${SCA_TMP_DIR}/sca.files"

if [ -r ${SCA_TMP_FILE} ]; then

    rm -f ${DIR}/ruleset/sca/* || true

    for sca_file in $(cat ${SCA_TMP_FILE}); do
        mv ${SCA_BASE_DIR}/${sca_file} ${DIR}/ruleset/sca
    done
fi

# Install the service
${INSTALLATION_SCRIPTS_DIR}/src/init/darwin-init.sh ${DIR}

# Remove temporary directory
rm -rf ${DIR}/packages_files

# Remove old ossec user and group if exists and change ownwership of files

if [[ $(dscl . -read /Groups/ossec) ]]; then
  find ${DIR}/ -group ossec -user root -exec chown root:wazuh {} \ > /dev/null 2>&1 || true
  if [[ $(dscl . -read /Users/ossec) ]]; then
    find ${DIR}/ -group ossec -user ossec -exec chown wazuh:wazuh {} \ > /dev/null 2>&1 || true
    sudo /usr/bin/dscl . -delete "/Users/ossec"
  fi
  sudo /usr/bin/dscl . -delete "/Groups/ossec"
fi

# Remove 4.1.5 patch
if [ -f ${DIR}/queue/alerts/sockets ]; then
  rm ${DIR}/queue/alerts/sockets
fi

if [ -n "${upgrade}" ] && [ -n "${restart}" ]; then
    ${DIR}/bin/wazuh-control restart
fi
