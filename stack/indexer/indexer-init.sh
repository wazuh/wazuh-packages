#!/bin/bash
# Wazuh Copyright (C) 2023 Wazuh Inc. (License GPLv2)
# Wazuh - indexer initialization script

INSTALL_PATH="/usr/share/wazuh-indexer"
BIN_PATH="${INSTALL_PATH}/bin"

main() {

    /bin/bash "${BIN_PATH}/indexer-security-init.sh"
    /bin/bash "${BIN_PATH}/indexer-ism-init.sh"

}

main "$@"

