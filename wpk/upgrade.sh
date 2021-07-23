#!/bin/bash
# Copyright (C) 2015-2020, Wazuh Inc.
(sleep 5 && chmod +x /opt/ossec/var/upgrade/*.sh && /opt/ossec/var/upgrade/pkg_installer.sh) >/dev/null 2>&1 &
