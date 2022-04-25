#! /bin/bash

set -ex

BRANCH=$1
JOBS=$2
DEBUG=$3
REVISION=$4
ZIP_NAME="windows_agent_${REVISION}.zip"

URL_REPO=https://github.com/wazuh/wazuh/archive/${BRANCH}.zip

# Download the wazuh repository
wget -O wazuh.zip ${URL_REPO} && unzip wazuh.zip

# Compile the wazuh agent for Windows
FLAGS="-j ${JOBS} "
VERSION=$(cat wazuh-*/src/VERSION | cut -dv -f2)
ZIP_SYMBOLS_NAME="wazuh-agent-windows-x86_64-debug-info-${VERSION}-${REVISION}.zip"

if [[ "${DEBUG}" = "yes" ]]; then
    FLAGS+="-d "
fi

rm /wazuh-*/src/symbols/.gitignore

make -C /wazuh-*/src deps TARGET=winagent ${FLAGS}

if [ ! -z "/tools" ]; then
    make -C /wazuh-*/src TARGET=winagent ${FLAGS} WIN_STRIP_TOOL_PATH=/tools
else
    make -C /wazuh-*/src TARGET=winagent ${FLAGS}
fi

if [ "$(ls -A /wazuh-*/src/symbols)" ]; then
    cd /wazuh-*/src/symbols && zip -r ${ZIP_SYMBOLS_NAME} .
    cd /wazuh-*/src/symbols && mv ${ZIP_SYMBOLS_NAME} /shared
    cd /
fi

rm -rf /wazuh-*/src/external
rm -rf /wazuh-*/src/symbols

# Zip the compiled agent and move it to the shared folder
zip -r ${ZIP_NAME} wazuh-*
cp ${ZIP_NAME} /shared
