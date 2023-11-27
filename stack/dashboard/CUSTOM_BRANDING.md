# Custom branding

Wazuh dashboard allows to apply a custom branding.

## Customize through OpenSearch Dashboards settings

This uses the built-in settings of OpenSearch Dashboards, for more information, see: https://opensearch.org/docs/2.10/dashboards/branding/

## Replace the default assets of Wazuh dashboard

This approach is useful for users that want to replace the default assets of the Wazuh dashboard as fallback instead of using the custom branding settings of OpenSearch Dashboards. Use case: revendors, IT security companies, custom package, etc...

The Wazuh dashboard package replaces the original files of OpenSearch Dashboards distribuible and rename it placing the files at `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/` directory. The customization can be done by replacing the assets.

| File | Theme | Description |
| --- | --- | --- |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch.svg` | - | Unused* |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_center_mark.svg` | - | Unused* |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_center_mark_on_dark.svg` | Dark | Unused* |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_center_mark_on_light.svg` | Dark | Unused* |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_dashboards.svg` | - | Unused* |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_dashboards_on_dark.svg` | Dark | Branding logo on expanded header |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_dashboards_on_light.svg` | Light | Branding logo on expanded header |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/wazuh_dashboard_login_background.svg` | Dark | Background of login page |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/wazuh_dashboard_login_mark.svg` | Dark | Branding logo on the login page |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_dashboards_spinner.svg` | - | Unused*  |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_dashboards_spinner_on_dark.svg` | Dark | Loading logo |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_dashboards_spinner_on_light.svg` | Light | Loading logo |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_mark.svg` | - | Unused* |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_mark_on_light.svg` | Light | ISO Branding logo when the expanded header is disabled |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_mark_on_dark.svg` | Dark | ISO Branding logo when the expanded header is disabled |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_on_light.svg` | Light | Unused* |
| `WAZUH_DASHBOARD_PATH/src/core/server/core_app/assets/logos/opensearch_on_dark.svg` | Dark | Unused* |

*The file was replaced.

> Note: The name of images includes the reference to `wazuh`, to customize this, it is needed to do changes in the production code of the Wazuh dashboard package, see `base/builder.sh`. This is not recommended if you don't know what should be done.
