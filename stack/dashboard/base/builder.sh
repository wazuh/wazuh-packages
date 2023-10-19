#!/bin/bash

# Wazuh dashboard base builder
# Copyright (C) 2021, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

set -e

# Script parameters to build the package
architecture="$1"
revision="$2"
future="$3"
repository="$4"
reference="$5"
opensearch_version="2.10.0"
base_dir=/opt/wazuh-dashboard-base

# -----------------------------------------------------------------------------

if [ -z "${revision}" ]; then
    revision="1"
fi

if [ "${architecture}" = "x86_64" ] || [ "${architecture}" = "amd64" ]; then
    architecture="x64"
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

# Obtain Wazuh plugin URL
if [ "${repository}" ];then
    valid_url='(https?|ftp|file)://[-[:alnum:]\+&@#/%?=~_|!:,.;]*[-[:alnum:]\+&@#/%=~_|]'
    if [[ $repository =~ $valid_url ]];then
        url="${repository}"
        if ! curl --output /dev/null --silent --head --fail "${url}"; then
            echo "The given URL to download the Wazuh plugin zip does not exist: ${url}"
            exit 1
        fi
    else
        url="https://packages-dev.wazuh.com/${repository}/ui/dashboard/wazuh-${version}-${revision}.zip"
    fi
else
    url="https://packages-dev.wazuh.com/pre-release/ui/dashboard/wazuh-${version}-${revision}.zip"
fi

# -----------------------------------------------------------------------------

mkdir -p /tmp/output
cd /opt

curl -sL https://artifacts.opensearch.org/releases/bundle/opensearch-dashboards/"${opensearch_version}"/opensearch-dashboards-"${opensearch_version}"-linux-${architecture}.tar.gz | tar xz

pip3 install pathfix.py
/usr/bin/pathfix.py -pni "/usr/bin/python3 -s" opensearch-dashboards-"${opensearch_version}" > /dev/null 2>&1

# Remove unnecessary files and set up configuration
mv opensearch-dashboards-* "${base_dir}"
cd "${base_dir}"
find -type l -exec rm -rf {} \;
rm -rf ./config/*
cp -r /root/stack/dashboard/base/files/etc ./
cp ./etc/custom_welcome/template.js.hbs ./src/legacy/ui/ui_render/bootstrap/template.js.hbs
cp ./etc/custom_welcome/light_theme.style.css ./src/core/server/core_app/assets/legacy_light_theme.css
cp ./etc/custom_welcome/*svg ./src/core/server/core_app/assets/
cp ./etc/custom_welcome/Assets/default_branding/logo_full_alpha.svg ./src/core/server/core_app/assets/default_branding/opensearch_logo_default_mode.svg
cp ./etc/custom_welcome/Assets/default_branding/logo_full_alpha.svg ./src/core/server/core_app/assets/default_branding/opensearch_logo_dark_mode.svg
cp ./etc/custom_welcome/Assets/default_branding/home.svg ./src/core/server/core_app/assets/default_branding/
cp ./etc/custom_welcome/Assets/default_branding/home_dark_mode.svg ./src/core/server/core_app/assets/default_branding/
cp ./etc/custom_welcome/Assets/Favicons/* ./src/core/server/core_app/assets/favicons/
cp ./etc/custom_welcome/Assets/Favicons/favicon.ico ./src/core/server/core_app/assets/favicons/favicon.ico
cp ./etc/http_service.js ./src/core/server/http/http_service.js
cp ./etc/template.js ./src/core/server/rendering/views/template.js
cp ./etc/styles.js ./src/core/server/rendering/views/styles.js
# Replace App Title
sed -i "s|defaultValue: ''|defaultValue: \'Wazuh\'|g" ./src/core/server/opensearch_dashboards_config.js
sed -i "90s|defaultValue: true|defaultValue: false|g" ./src/core/server/opensearch_dashboards_config.js
# Replace config path
sed -i "s'\$DIR/config'/etc/wazuh-dashboard'g" ./bin/opensearch-dashboards-keystore
sed -i "s'\$DIR/config'/etc/wazuh-dashboard'g" ./bin/opensearch-dashboards-plugin
# Add fix to Node variables as Node is not using the NODE_OPTIONS environment variables
sed -i 's/NODE_OPTIONS="$OSD_NODE_OPTS_PREFIX $OSD_NODE_OPTS $NODE_OPTIONS"/NODE_OPTIONS="$OSD_NODE_OPTS_PREFIX $OSD_NODE_OPTS $NODE_OPTIONS"\n/g' ./bin/use_node
sed -i 's/exec "${NODE}"/NODE_ENV=production exec "${NODE}" ${NODE_OPTIONS} /g' ./bin/use_node
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
sed -i 's|href:opensearchDashboardsDocLink,|href:"https://documentation.wazuh.com/'${wazuh_minor}'",|' ./src/core/target/public/core.entry.js
## Help link - Ask OpenSearch
sed -i 's|Ask OpenSearch|Ask Wazuh|' ./src/core/target/public/core.entry.js
sed -i 's|OPENSEARCH_DASHBOARDS_ASK_OPENSEARCH_LINK="https://github.com/opensearch-project"|OPENSEARCH_DASHBOARDS_ASK_OPENSEARCH_LINK="https://wazuh.com/community/join-us-on-slack"|' ./src/core/target/public/core.entry.js
## Help link - Give feedback
sed -i 's|OPENSEARCH_DASHBOARDS_FEEDBACK_LINK="https://github.com/opensearch-project"|OPENSEARCH_DASHBOARDS_FEEDBACK_LINK="https://wazuh.com/community/join-us-on-slack"|' ./src/core/target/public/core.entry.js
## Help link - Open an issue in GitHub
sed -i 's|GITHUB_CREATE_ISSUE_LINK="https://github.com/opensearch-project/OpenSearch-Dashboards/issues/new/choose"|GITHUB_CREATE_ISSUE_LINK="https://github.com/wazuh/wazuh/issues/new/choose"|' ./src/core/target/public/core.entry.js
# Replace home logo
sed -i 's|DEFAULT_MARK="opensearch_mark_default_mode.svg"|DEFAULT_MARK="home.svg"|g' ./src/core/target/public/core.entry.js
sed -i 's|DEFAULT_DARK_MARK="opensearch_mark_dark_mode.svg"|DEFAULT_DARK_MARK="home_dark_mode.svg"|g' ./src/core/target/public/core.entry.js
# Build the compressed files
gzip -c ./src/core/target/public/core.entry.js > ./src/core/target/public/core.entry.js.gz
brotli -c ./src/core/target/public/core.entry.js > ./src/core/target/public/core.entry.js.br
# Remove Overview plugin from the OpenSearch Dashboards menu.
# Remove "updater" property and set the plugin "status" as inaccesible (status:1)
sed -i 's|updater\$:appUpdater\$|status:1|' ./src/plugins/opensearch_dashboards_overview/target/public/opensearchDashboardsOverview.plugin.js
gzip -c ./src/plugins/opensearch_dashboards_overview/target/public/opensearchDashboardsOverview.plugin.js > ./src/plugins/opensearch_dashboards_overview/target/public/opensearchDashboardsOverview.plugin.js.gz
brotli -c ./src/plugins/opensearch_dashboards_overview/target/public/opensearchDashboardsOverview.plugin.js > ./src/plugins/opensearch_dashboards_overview/target/public/opensearchDashboardsOverview.plugin.js.br
# Remove "New to OpenSearch Dashboards" message with link to OpenSearch Dashboards sample data in Dashboard plugin
# Removed file on OSD 2.10.0
# sed -i 's|external_osdSharedDeps_React_default.a.createElement("p",null,external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_OsdI18nReact_\["FormattedMessage"\],{id:"dashboard.listing.createNewDashboard.newToOpenSearchDashboardsDescription",defaultMessage:"New to OpenSearch Dashboards|false\&\&external_osdSharedDeps_React_default.a.createElement("p",null,external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_OsdI18nReact_["FormattedMessage"],{id:"dashboard.listing.createNewDashboard.newToOpenSearchDashboardsDescription",defaultMessage:"New to OpenSearch Dashboards|' ./src/plugins/dashboard/target/public/dashboard.chunk.1.js
# gzip -c ./src/plugins/dashboard/target/public/dashboard.chunk.1.js > ./src/plugins/dashboard/target/public/dashboard.chunk.1.js.gz
# brotli -c ./src/plugins/dashboard/target/public/dashboard.chunk.1.js > ./src/plugins/dashboard/target/public/dashboard.chunk.1.js.br
# Remove `home` button from the sidebar menu
sed -i 's|\["EuiHorizontalRule"\],{margin:"none"})),external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_ElasticEui_\["EuiFlexItem"\],{grow:false,style:{flexShrink:0}},external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_ElasticEui_\["EuiCollapsibleNavGroup"\]|["EuiHorizontalRule"],{margin:"none"})),false\&\&external_osdSharedDeps_React_default.a.createElem(external_osdSharedDeps_ElasticEui_["EuiFlexItem"],{grow:false,style:{flexShrink:0}},external_osdSharedDeps_React_default.a.createElement(external_osdSharedDeps_ElasticEui_["EuiCollapsibleNavGroup"]|' ./src/core/target/public/core.entry.js
# Replace OpenSearch login default configuration title with Wazuh login title text
sed -i 's|Log in to OpenSearch Dashboards||g' ./plugins/securityDashboards/server/index.js
sed -i 's|If you have forgotten your username or password, contact your system administrator.||g' ./plugins/securityDashboards/server/index.js
# Replace OpenSearch login logo with Wazuh login logo
sed -i 's|opensearch_logo_h_default.a|"/ui/Wazuh-Logo.svg"|g' ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js
# Replace OpenSearch login title with Wazuh login title
sed -i 's|Log in to OpenSearch Dashboards||g' ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js
# Replace OpenSearch login subtitle with Wazuh login subtitle
sed -i 's|If you have forgotten your username or password, contact your system administrator.||g' ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js
# Disable first time pop-up tenant selector
sed -i 's|setShouldShowTenantPopup(shouldShowTenantPopup)|setShouldShowTenantPopup(false)|g' ./plugins/securityDashboards/target/public/securityDashboards.plugin.js
# Replace home logo
sed -i 's|DEFAULT_MARK="opensearch_mark_default_mode.svg"|DEFAULT_MARK="home.svg"|g' ./plugins/securityDashboards/target/public/securityDashboards.plugin.js
sed -i 's|DEFAULT_DARK_MARK="opensearch_mark_dark_mode.svg"|DEFAULT_DARK_MARK="home_dark_mode.svg"|g' ./plugins/securityDashboards/target/public/securityDashboards.plugin.js
gzip -c ./plugins/securityDashboards/target/public/securityDashboards.plugin.js > ./plugins/securityDashboards/target/public/securityDashboards.plugin.js.gz
brotli -c ./plugins/securityDashboards/target/public/securityDashboards.plugin.js > ./plugins/securityDashboards/target/public/securityDashboards.plugin.js.br

# Generate compressed files
gzip -c ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js > ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js.gz
brotli -c ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js > ./plugins/securityDashboards/target/public/securityDashboards.chunk.5.js.br

# Define categories
category_explore='{id:"explore",label:"Explore",order:500,euiIconType:"search"}'
category_dashboard_management='{id:"management",label:"Indexer/dashboard Management",order:5e3,euiIconType:"managementApp"}'

# Add custom categories (explore) to the built-in
sed -i -e "s|DEFAULT_APP_CATEGORIES=Object.freeze({|DEFAULT_APP_CATEGORIES=Object.freeze({explore:${category_explore},|" ./src/core/target/public/core.entry.js

# Replace management built-in app category
sed -i -e "s|management:{id:\"management\",label:external_osdSharedDeps_OsdI18n_\[\"i18n\"\].translate(\"core.ui.managementNavList.label\",{defaultMessage:\"Management\"}),order:5e3,euiIconType:\"managementApp\"}|management:${category_dashboard_management}|" ./src/core/target/public/core.entry.js

# Replace app category to Discover app
sed -i -e 's|category:core_public_\["DEFAULT_APP_CATEGORIES"\].opensearchDashboards|category:core_public_["DEFAULT_APP_CATEGORIES"].explore|' ./src/plugins/discover/target/public/discover.plugin.js

# Replace app category to Dashboard app
sed -i -e 's|category:core_public_\["DEFAULT_APP_CATEGORIES"\].opensearchDashboards|category:core_public_["DEFAULT_APP_CATEGORIES"].explore|' ./src/plugins/dashboard/target/public/dashboard.plugin.js

# Replace app category to Visualize app
sed -i -e 's|category:core_public_\["DEFAULT_APP_CATEGORIES"\].opensearchDashboards|category:core_public_["DEFAULT_APP_CATEGORIES"].explore|' ./src/plugins/visualize/target/public/visualize.plugin.js

# Replace app category to Reporting app
sed -i -e "s|category:{id:\"opensearch\",label:_i18n.i18n.translate(\"opensearch.reports.categoryName\",{defaultMessage:\"OpenSearch Plugins\"}),order:2e3}|category:${category_explore}|" ./plugins/reportsDashboards/target/public/reportsDashboards.plugin.js

# Replace app category to Alerting app
sed -i -e "s|category:{id:\"opensearch\",label:\"OpenSearch Plugins\",order:2e3}|category:${category_explore}|" ./plugins/alertingDashboards/target/public/alertingDashboards.plugin.js

# Replace app category to Maps app
sed -i -e "s|category:{id:\"opensearch\",label:\"OpenSearch Plugins\",order:2e3}|category:${category_explore}|" ./plugins/customImportMapDashboards/target/public/customImportMapDashboards.plugin.js

# Replace app category to Notifications app
sed -i -e "s|category:DEFAULT_APP_CATEGORIES.management|category:${category_explore}|" ./plugins/notificationsDashboards/target/public/notificationsDashboards.plugin.js

# Replace app category to Index Management app 
sed -i -e "s|category:DEFAULT_APP_CATEGORIES.management|category:${category_dashboard_management}|g" ./plugins/indexManagementDashboards/target/public/indexManagementDashboards.plugin.js

# Replace app category to Dev Tools app
sed -i -e "s|category:public_["DEFAULT_APP_CATEGORIES"].management|category:${category_dashboard_management}|g" ./src/plugins/dev_tools/target/public/devTools.plugin.js

# Replace app category to Dashboards Management (Stack management) app
sed -i -e "s|category:public_["DEFAULT_APP_CATEGORIES"].management|category:${category_dashboard_management}|g" ./src/plugins/management/target/public/management.plugin.js

# Replace app category to Security app
sed -i -e "s|category:DEFAULT_APP_CATEGORIES.management|category:${category_dashboard_management}|g" ./plugins/securityDashboards/target/public/securityDashboards.plugin.js

# Replace app order to Discover app
app_order_discover=1000
sed -i -e "s|order:1e3|order:${app_order_discover}|g" ./src/plugins/discover/target/public/discover.plugin.js

# Replace app order to Discover app
app_order_dashboard=1010
sed -i -e "s|order:2500|order:${app_order_dashboard}|g" ./src/plugins/dashboard/target/public/dashboard.plugin.js

# Replace app order to Visualize app
app_order_visualize=1020
sed -i -e "s|order:8e3|order:${app_order_visualize}|g" ./src/plugins/visualize/target/public/visualize.plugin.js

# Replace app order to Dev tools app
app_order_dev_tools=9010
sed -i -e "s|order:9070|order:${app_order_dev_tools}|g" ./src/plugins/dev_tools/target/public/devTools.plugin.js

# Replace app order to Dashboard management app
app_order_dashboard_management=9020
sed -i -e "s|order:9030|order:${app_order_dashboard_management}|g" ./src/plugins/management/target/public/management.plugin.js

# Replace app order to Security app
app_order_security=9030
sed -i -e "s|order:9050|order:${app_order_security}|g" ./plugins/securityDashboards/target/public/securityDashboards.plugin.js

# Replace app order to Index management app
app_order_index_management=9040
sed -i -e "s|order:9010|order:${app_order_index_management}|g" ./plugins/indexManagementDashboards/target/public/indexManagementDashboards.plugin.js

# Replace app order to Snapshot management app
app_order_snapshot_management=9050
sed -i -e "s|order:9020|order:${app_order_snapshot_management}|g" ./plugins/indexManagementDashboards/target/public/indexManagementDashboards.plugin.js

# Avoid the management Overview application is registered to feature catalogue
sed -i -e "s|home.featureCatalogue|false \&\& home.featureCatalogue|g" ./src/plugins/management_overview/target/public/managementOverview.plugin.js

# Avoid the management Overview application is registered (appear on side menu)
sed -i -e "s|application.register|false \&\& application.register|g" ./src/plugins/management_overview/target/public/managementOverview.plugin.js

files_to_recreate=(
    ./src/core/target/public/core.entry.js
    ./src/plugins/discover/target/public/discover.plugin.js
    ./src/plugins/dashboard/target/public/dashboard.plugin.js
    ./src/plugins/visualize/target/public/visualize.plugin.js
    ./plugins/reportsDashboards/target/public/reportsDashboards.plugin.js
    ./plugins/alertingDashboards/target/public/alertingDashboards.plugin.js
    ./plugins/customImportMapDashboards/target/public/customImportMapDashboards.plugin.js
    ./plugins/notificationsDashboards/target/public/notificationsDashboards.plugin.js
    ./plugins/indexManagementDashboards/target/public/indexManagementDashboards.plugin.js
    ./src/plugins/dev_tools/target/public/devTools.plugin.js
    ./src/plugins/management/target/public/management.plugin.js
    ./plugins/securityDashboards/target/public/securityDashboards.plugin.js
    ./src/plugins/management_overview/target/public/managementOverview.plugin.js
)

for value in "${files_to_recreate[@]}"
do
    gzip -c "$value" > "$value.gz"
    brotli -c "$value" > "$value.br"
done

# Add VERSION file
cp /root/VERSION .
# Add exception for wazuh plugin install
wazuh_plugin="if (plugin.includes(\'wazuh\')) {\n    return plugin;\n  } else {\n    return \`\${LATEST_PLUGIN_BASE_URL}\/\${version}\/latest\/\${platform}\/\${arch}\/tar\/builds\/opensearch-dashboards\/plugins\/\${plugin}-\${version}.zip\`;\n  }"
sed -i "s|return \`\${LATEST_PLUGIN_BASE_URL}\/\${version}\/latest\/\${platform}\/\${arch}\/tar\/builds\/opensearch-dashboards\/plugins\/\${plugin}-\${version}.zip\`;|$wazuh_plugin|" ./src/cli_plugin/install/settings.js
# Generate build number for package.json
curl -sO ${url}
unzip *.zip 'opensearch-dashboards/wazuh/package.json'
build_number=$(jq -r '.version' ./opensearch-dashboards/wazuh/package.json | tr -d '.')$(jq -r '.revision' ./opensearch-dashboards/wazuh/package.json)
rm -rf ./opensearch-dashboards
rm -f ./*.zip
jq ".build.number=${build_number}" ./package.json > ./package.json.tmp
mv ./package.json.tmp ./package.json


# Remove plugins
/bin/bash ./bin/opensearch-dashboards-plugin remove queryWorkbenchDashboards --allow-root
/bin/bash ./bin/opensearch-dashboards-plugin remove anomalyDetectionDashboards --allow-root
/bin/bash ./bin/opensearch-dashboards-plugin remove observabilityDashboards --allow-root
/bin/bash ./bin/opensearch-dashboards-plugin remove securityAnalyticsDashboards --allow-root
/bin/bash ./bin/opensearch-dashboards-plugin remove searchRelevanceDashboards --allow-root

find -type d -exec chmod 750 {} \;
find -type f -perm 644 -exec chmod 640 {} \;
find -type f -perm 755 -exec chmod 750 {} \;
find -type f -perm 744 -exec chmod 740 {} \;


# -----------------------------------------------------------------------------

# Base output
cd /opt
tar -cJf wazuh-dashboard-base-"${version}"-"${revision}"-linux-${architecture}.tar.xz wazuh-dashboard-base
cp wazuh-dashboard-base-"${version}"-"${revision}"-linux-${architecture}.tar.xz /tmp/output/
