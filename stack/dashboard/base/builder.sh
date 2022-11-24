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
revision="${3}"
reference="${4}"
base_dir=/tmp/output/wazuh-dashboard-base

# -----------------------------------------------------------------------------

if [ -z "${revision}" ]; then
    revision="1"
fi

# Including files
if [ "${reference}" ];then
    curl -sL https://github.com/wazuh/wazuh-packages/tarball/"${reference}" | tar xz
    cp -r ./wazuh*/* /root/
    version=$(curl -sL https://raw.githubusercontent.com/wazuh/wazuh-packages/${reference}/VERSION | cat)
else
    version=$(cat /root/VERSION)
fi
if [ "${future}" = "yes" ];then
    version="99.99.0"
fi
wazuh_minor=$(echo ${version} | cut -c1-3)

# -----------------------------------------------------------------------------

mkdir -p /tmp/output
cd /tmp/output

curl -sL https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/"${opensearch_version}"/opensearch-dashboards-"${opensearch_version}"-linux-x64.tar.gz | tar xz

# Remove unnecessary files and set up configuration
mv opensearch-dashboards-* "${base_dir}"
cd "${base_dir}"
find -type l -exec rm -rf {} \;
rm -rf ./config/*
cp -r /root/stack/dashboard/base/files/etc ./
cp ./etc/custom_welcome/template.js.hbs ./src/legacy/ui/ui_render/bootstrap/template.js.hbs
cp ./etc/custom_welcome/light_theme.style.css ./src/core/server/core_app/assets/legacy_light_theme.css
cp ./etc/custom_welcome/*svg ./src/core/server/core_app/assets/
cp ./etc/custom_welcome/Assets/default_branding/Solid_black.svg ./src/core/server/core_app/assets/default_branding/opensearch_logo.svg
cp ./etc/custom_welcome/Assets/Favicons/* ./src/core/server/core_app/assets/favicons/
cp ./etc/custom_welcome/Assets/Favicons/favicon.ico ./src/core/server/core_app/assets/favicons/favicon.ico
cp ./etc/http_service.js ./src/core/server/http/http_service.js
cp ./etc/template.js ./src/core/server/rendering/views/template.js
# Replace App Title
sed -i "s|defaultValue: ''|defaultValue: \'Wazuh\'|g" ./src/core/server/opensearch_dashboards_config.js
# Replace config path
sed -i "s'\$DIR/config'/etc/wazuh-dashboard'g" ./bin/opensearch-dashboards
sed -i "s'\$DIR/config'/etc/wazuh-dashboard'g" ./bin/opensearch-dashboards-keystore
sed -i "s'\$DIR/config'/etc/wazuh-dashboard'g" ./bin/opensearch-dashboards-plugin
sed -i "s'NODE_OPTIONS=\"--no-warnings --max-http-header-size=65536 \$OSD_NODE_OPTS \$NODE_OPTIONS\" NODE_ENV=production exec \"\${NODE}\" \"\${DIR}/src/cli/dist\" \${@}'NODE_OPTIONS=\"--no-warnings --max-http-header-size=65536 \$OSD_NODE_OPTS \$NODE_OPTIONS\"'g" ./bin/opensearch-dashboards
echo "NODE_ENV=production exec \"\${NODE}\" \${NODE_OPTIONS} \"\${DIR}/src/cli/dist\" \${@}" >> ./bin/opensearch-dashboards
# Replace the redirection to `home` in the header logo
sed -i "s'/app/home'/app/wazuh'g" ./src/core/target/public/core.entry.js
# Replace others redirections to `home`
sed -i 's/navigateToApp("home")/navigateToApp("wazuh")/g' ./src/core/target/public/core.entry.js
# Changed from Opensearch Documentation links to Wazuh Documentation
# Help menu
## Help header - Version
sed -i 's|"core.ui.chrome.headerGlobalNav.helpMenuVersion",defaultMessage:"v {version}"|"core.ui.chrome.headerGlobalNav.helpMenuVersion",defaultMessage:"v'${version}'"|' ./src/core/target/public/core.entry.js
## Help link - OpenSearch Dashboards documentation
sed -i 's|OpenSearch Dashboards documentation|Wazuh documentation|' ./src/core/target/public/core.entry.js
sed -i 's|OPENSEARCH_DASHBOARDS_DOCS="https://opensearch.org/docs/dashboards/"|OPENSEARCH_DASHBOARDS_DOCS="https://documentation.wazuh.com/'${wazuh_minor}'"|' ./src/core/target/public/core.entry.js
## Help link - Ask OpenSearch
sed -i 's|Ask OpenSearch|Ask Wazuh|' ./src/core/target/public/core.entry.js
sed -i 's|OPENSEARCH_DASHBOARDS_ASK_OPENSEARCH_LINK="https://github.com/opensearch-project"|OPENSEARCH_DASHBOARDS_ASK_OPENSEARCH_LINK="https://wazuh.com/community/join-us-on-slack"|' ./src/core/target/public/core.entry.js
## Help link - Give feedback
sed -i 's|OPENSEARCH_DASHBOARDS_FEEDBACK_LINK="https://github.com/opensearch-project"|OPENSEARCH_DASHBOARDS_FEEDBACK_LINK="https://wazuh.com/community/join-us-on-slack"|' ./src/core/target/public/core.entry.js
## Help link - Open an issue in GitHub
sed -i 's|GITHUB_CREATE_ISSUE_LINK="https://github.com/opensearch-project/OpenSearch-Dashboards/issues/new/choose"|GITHUB_CREATE_ISSUE_LINK="https://github.com/wazuh/wazuh/issues/new/choose"|' ./src/core/target/public/core.entry.js
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
sed -i 's|Please login to OpenSearch Dashboards||g' ./plugins/securityDashboards/server/index.js
sed -i 's|If you have forgotten your username or password, please ask your system administrator||g' ./plugins/securityDashboards/server/index.js
# Replace OpenSearch login logo with Wazuh login logo
sed -i 's|opensearch_logo_h_default.a|"/ui/Wazuh-Logo.svg"|g' ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js
# Replace OpenSearch login title with Wazuh login title
sed -i 's|Please login to OpenSearch Dashboards||g' ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js
# Replace OpenSearch login subtitle with Wazuh login subtitle
sed -i 's|If you have forgotten your username or password, please ask your system administrator||g' ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js
# Disable first time pop-up tenant selector
sed -i 's|setShouldShowTenantPopup(shouldShowTenantPopup)|setShouldShowTenantPopup(false)|g' ./plugins/securityDashboards/target/public/securityDashboards.plugin.js
gzip -c ./plugins/securityDashboards/target/public/securityDashboards.plugin.js > ./plugins/securityDashboards/target/public/securityDashboards.plugin.js.gz
brotli -c ./plugins/securityDashboards/target/public/securityDashboards.plugin.js > ./plugins/securityDashboards/target/public/securityDashboards.plugin.js.br
# Change the python version used, so rmpbuild 4.14 doesn't give an error
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/pylib/gyp/MSVSSettings_test.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/pylib/gyp/__init__.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/pylib/gyp/flock_tool.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/pylib/gyp/mac_tool.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/pylib/gyp/generator/msvs_test.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/pylib/gyp/easy_xml_test.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/pylib/gyp/common_test.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/pylib/gyp/input_test.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/pylib/gyp/win_tool.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/test_gyp.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/tools/pretty_vcproj.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/tools/pretty_sln.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/tools/graphviz.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/tools/pretty_gyp.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/gyp_main.py
sed -i 's|#!/usr/bin/env python|#!/usr/bin/env python3|g' ./node_modules/node-gyp/gyp/setup.py
sed -i 's|#!/usr/bin/python|#!/usr/bin/python3|g' ./node_modules/re2/vendor/re2/make_unicode_groups.py
sed -i 's|#!/usr/bin/python|#!/usr/bin/python3|g' ./node_modules/re2/vendor/re2/make_unicode_casefold.py

# Generate compressed files
gzip -c ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js > ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js.gz
brotli -c ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js > ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js.br
# Add VERSION file
cp /root/VERSION .

# Remove plugins
/bin/bash ./bin/opensearch-dashboards-plugin remove queryWorkbenchDashboards --allow-root
/bin/bash ./bin/opensearch-dashboards-plugin remove anomalyDetectionDashboards --allow-root
/bin/bash ./bin/opensearch-dashboards-plugin remove observabilityDashboards --allow-root

find -type d -exec chmod 750 {} \;
find -type f -perm 644 -exec chmod 640 {} \;
find -type f -perm 755 -exec chmod 750 {} \;


# -----------------------------------------------------------------------------

# Base output
cd /tmp/output
tar -cJf wazuh-dashboard-base-"${version}"-"${revision}"-linux-x64.tar.xz wazuh-dashboard-base
rm -rf "${base_dir}"