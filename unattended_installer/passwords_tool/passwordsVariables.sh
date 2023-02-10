# Passwords tool - variables
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

readonly logfile="/var/log/wazuh-passwords-tool.log"
debug=">> ${logfile} 2>&1"
adminpem="/etc/wazuh-indexer/certs/admin.pem"
adminkey="/etc/wazuh-indexer/certs/admin-key.pem"