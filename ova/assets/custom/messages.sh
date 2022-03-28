#!/bin/sh

DEBUG=$1
WAZUH_VERSION=$2
SYSTEM_USER=$3

[[ ${DEBUG} = "yes" ]] && set -ex || set -e

# OVA Welcome message
cat > /etc/issue <<EOF

Welcome to the Wazuh OVA version
Wazuh - ${WAZUH_VERSION}
Use wazuh/wazuh to login
Thank you for using Wazuh!

EOF

# User Welcome message
cat > /etc/motd <<EOF


        WWWWWW            WWWWWW           WWWWWW
         WWWWWW          WWWWWWWW          WWWWWW
          WWWWWW        WWWWWWWWWW        WWWWWW
          &WWWWW       WWWWW WWWWW       WWWWWW
           WWWWWW     WWWWWW  WWWWW     WWWWWW
            WWWWWW    WWWWW    WWWWW    WWWWW
             WWWWWW  WWWWW      WWWWW  WWWWWW
             /WWWWW,WWWWW       WWWWW WWWWWW
              WWWWWWWWWW         WWWWWWWWWW         WWWWW
               WWWWWWWW.          WWWWWWWW        WWWWWWWWW
                WWWWWWW            WWWWWW&        WWWWWWWWW
                 WWWWW              WWWWW          .WWWWW%



         WAZUH Open Source Security Platform
                   www.wazuh.com

EOF
