#!/bin/bash

echo "Installing Wazuh Manager."
yum install $PACKAGE_NAME

echo "Enabling Wazuh Agent."
systemctl daemon-reload
systemctl enable wazuh-manager