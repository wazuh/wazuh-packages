#! /bin/bash

set -ex

BRANCH=$1
JOBS=$2
DEBUG=$3
REVISION=$4

URL_REPO=https://github.com/wazuh/wazuh/archive/${BRANCH}.zip

# Download the wazuh repository
wget -O wazuh.zip ${URL_REPO} && unzip wazuh.zip

# Compile the wazuh agent for Windows
FLAGS="-j ${JOBS} "

if [[ "${DEBUG}" = "yes" ]]; then
    FLAGS+="-d "
fi

make -C /wazuh-*/src deps ${FLAGS} 
make -C /wazuh-*/src TARGET=winagent ${FLAGS} 

# Zip the compiled agent and move it to the shared folder
zip -r wazuh-${BRANCH}.zip wazuh-*
cp  wazuh-${BRANCH}.zip /shared