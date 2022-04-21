#!/bin/bash

# Wazuh dashboard base builder
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -ex

# Script parameters to build the package
opensearch_version="${1}"
future="${2}"
reference="${3}"
BASE_DIR=/tmp/output/wazuh-dashboard-base

# -----------------------------------------------------------------------------

# Including files
if [ "${reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/"${reference}" | tar xz
    cp -r ./wazuh*/* /root/
    version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${spec_reference}/VERSION | cat)
else
    version=$(cat /root/VERSION)
fi
if [ "${future}" = "yes" ];then
    version="99.99.0"
fi


# -----------------------------------------------------------------------------

mkdir -p /tmp/output
cd /tmp/output

if [ -z "${release}" ]; then
    release="1"
fi

curl -sL https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/"${opensearch_version}"/opensearch-dashboards-"${opensearch_version}"-linux-x64.tar.gz | tar xz

# Remove unnecessary files and set up configuration
mv opensearch-dashboards-* "${BASE_DIR}"
cd "${BASE_DIR}"
find -type l -exec rm -rf {} \;
rm -rf ./config/*
cp -r /root/stack/dashboard/base/files/etc ./
cp ./etc/custom_welcome/template.js.hbs ./src/legacy/ui/ui_render/bootstrap/template.js.hbs
cp ./etc/custom_welcome/light_theme.style.css ./src/core/server/core_app/assets/legacy_light_theme.css
cp ./etc/custom_welcome/*svg ./src/core/server/core_app/assets/
cp ./etc/custom_welcome/Assets/default_branding/Solid_black.svg ./src/core/server/core_app/assets/default_branding/opensearch_logo.svg
cp ./etc/custom_welcome/Assets/Favicons/* ./src/core/server/core_app/assets/favicons/
cp ./etc/custom_welcome/Assets/Favicons/favicon-32x32.png ./src/core/server/core_app/assets/favicons/favicon.ico
cp ./etc/opensearch_dashboards_config.js ./src/core/server/opensearch_dashboards_config.js
cp ./etc/http_service.js ./src/core/server/http/http_service.js
# Replace config path
sed -i "s'\$DIR/config'/etc/wazuh-dashboard'g" ./bin/opensearch-dashboards
sed -i "s'\$DIR/config'/etc/wazuh-dashboard'g" ./bin/opensearch-dashboards-keystore
sed -i "s'\$DIR/config'/etc/wazuh-dashboard'g" ./bin/opensearch-dashboards-plugin
# Replace the redirection to `home` in the header logo
sed -i "s'/app/home'/app/wazuh'g" ./src/core/target/public/core.entry.js
# Replace others redirections to `home`
sed -i 's/navigateToApp("home")/navigateToApp("wazuh")/g' ./src/core/target/public/core.entry.js
# Build the compressed files
gzip -c ./src/core/target/public/core.entry.js > ./src/core/target/public/core.entry.js.gz
brotli -c ./src/core/target/public/core.entry.js > ./src/core/target/public/core.entry.js.br
# Remove Overview plugin from the OpenSearch Dashboards menu.
# Remove "updater" property and set the plugin "status" as inaccesible (status:1)
sed -i 's|updater\$:appUpdater\$|status:1|' ./src/plugins/opensearch_dashboards_overview/target/public/opensearchDashboardsOverview.plugin.js
gzip -c ./src/plugins/opensearch_dashboards_overview/target/public/opensearchDashboardsOverview.plugin.js > ./src/plugins/opensearch_dashboards_overview/target/public/opensearchDashboardsOverview.plugin.js.gz
brotli -c ./src/plugins/opensearch_dashboards_overview/target/public/opensearchDashboardsOverview.plugin.js > ./src/plugins/opensearch_dashboards_overview/target/public/opensearchDashboardsOverview.plugin.js.br
# Remove "New to OpenSearch Dashboards" message with link to OpenSearch Dashboards sample data in Dashboard plugin
sed -i 's|external_osdSharedDeps_React_default.a.createElement("p",null,external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_OsdI18nReact_\["FormattedMessage"\],{id:"dashboard.listing.createNewDashboard.newToOpenSearchDashboardsDescription",defaultMessage:"New to OpenSearch Dashboards|false\&\&external_osdSharedDeps_React_default.a.createElement("p",null,external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_OsdI18nReact_["FormattedMessage"],{id:"dashboard.listing.createNewDashboard.newToOpenSearchDashboardsDescription",defaultMessage:"New to OpenSearch Dashboards|' ./src/plugins/dashboard/target/public/dashboard.chunk.1.js
gzip -c ./src/plugins/dashboard/target/public/dashboard.chunk.1.js > ./src/plugins/dashboard/target/public/dashboard.chunk.1.js.gz
brotli -c ./src/plugins/dashboard/target/public/dashboard.chunk.1.js > ./src/plugins/dashboard/target/public/dashboard.chunk.1.js.br
# Remove `home` button from the sidebar menu
sed -i 's|\["EuiHorizontalRule"\],{margin:"none"})),external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_ElasticEui_\["EuiFlexItem"\],{grow:false,style:{flexShrink:0}},external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_ElasticEui_\["EuiCollapsibleNavGroup"\]|["EuiHorizontalRule"],{margin:"none"})),false\&\&external_osdSharedDeps_React_default.a.createElem(external_osdSharedDeps_ElasticEui_["EuiFlexItem"],{grow:false,style:{flexShrink:0}},external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_ElasticEui_["EuiCollapsibleNavGroup"]|' ./src/core/target/public/core.entry.js
# Replace OpenSearch login default configuration title with Wazuh login title text
sed -i 's|Please login to OpenSearch Dashboards|Welcome to Wazuh|g' ./plugins/securityDashboards/server/index.js
sed -i 's|If you have forgotten your username or password, please ask your system administrator|The Open Source Security Platform|g' ./plugins/securityDashboards/server/index.js
# Replace OpenSearch login logo with Wazuh login logo
sed -i 's|opensearch_logo_h_default.a|"/ui/wazuh_logo_circle.svg"|g' ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js
# Replace OpenSearch login title with Wazuh login title
sed -i 's|Please login to OpenSearch Dashboards|Welcome to Wazuh|g' ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js
# Replace OpenSearch login subtitle with Wazuh login subtitle
sed -i 's|If you have forgotten your username or password, please ask your system administrator|The Open Source Security Platform|g' ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js
# Disable first time pop-up tenant selector
sed -i 's|setShouldShowTenantPopup(shouldShowTenantPopup)|setShouldShowTenantPopup(false)|g' ./plugins/securityDashboards/target/public/securityDashboards.plugin.js
gzip -c ./plugins/securityDashboards/target/public/securityDashboards.plugin.js > ./plugins/securityDashboards/target/public/securityDashboards.plugin.js.gz
brotli -c ./plugins/securityDashboards/target/public/securityDashboards.plugin.js > ./plugins/securityDashboards/target/public/securityDashboards.plugin.js.br
# Generate compressed files
gzip -c ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js > ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js.gz
brotli -c ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js > ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js.br

find -type d -exec chmod 750 {} \;
find -type f -perm 644 -exec chmod 640 {} \;
find -type f -perm 755 -exec chmod 750 {} \;


# -----------------------------------------------------------------------------

# Base output
cd /tmp/output
tar -cJf wazuh-dashboard-base-"${version}"-linux-x64.tar.xz wazuh-dashboard-base
rm -rf "${BASE_DIR}"