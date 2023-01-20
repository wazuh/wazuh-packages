#!/bin/bash

echo "Installing Wazuh Agent."
yum install $PACKAGE_NAME

echo "Enabling Wazuh Agent."
systemctl daemon-reload
systemctl enable wazuh-agent