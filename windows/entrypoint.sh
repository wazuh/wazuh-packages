#! /bin/bash

set -ex

BRANCH=$1
JOBS=$2
DEBUG=$3
REVISION=$4
ZIP_NAME="compiled_agent.zip"

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

rm -rf /wazuh-*/src/external

# Zip the compiled agent and move it to the shared folder
zip -r ${ZIP_NAME} wazuh-*
cp ${ZIP_NAME} /shared