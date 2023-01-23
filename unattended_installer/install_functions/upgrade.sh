# Wazuh installer - common.sh functions.
# Copyright (C) 2015, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.


function upgrade_getUpgradable {

  if [ -n "${wazuh_installed}" ]; then
    if [ "${sys_type}" == "yum" ]; then
        manager_upgradable=$(yum list wazuh-manager --showduplicates | tail -n +8 | grep -A 5000 ${wazuh_installed} | tail -n +2 | grep ${wazuh_version})
    elif [ "${sys_type}" == "apt-get" ]; then
        manager_upgradable=$(apt-get install wazuh-manager=${wazuh_version}-* --dry-run |grep "The following packages will be upgraded:")
    fi
  fi

  if [ -n "${filebeat_installed}" ]; then
    if [ "${sys_type}" == "yum" ]; then
        filebeat_upgradable=$(yum list filebeat --showduplicates | tail -n +8 | grep -A 5000 ${filebeat_installed} | tail -n +2 | grep ${filebeat_version})
    elif [ "${sys_type}" == "apt-get" ]; then
        filebeat_upgradable=$(apt-get install filebeat=${filebeat_version} --dry-run |grep "The following packages will be upgraded:")
    fi
    installed_module_version=$(cat /usr/share/filebeat/module/wazuh/alerts/manifest.yml | grep "module_version" | cut -d" " -f2)
    installed_module_version_major=$(echo ${installed_module_version} | cut -d"." -f1)
    installed_module_version_minor=$(echo ${installed_module_version} | cut -d"." -f2)
    filebeat_wazuh_module_major=$(echo ${filebeat_wazuh_module_version} | cut -d"." -f1)
    filebeat_wazuh_module_minor=$(echo ${filebeat_wazuh_module_version} | cut -d"." -f2)
    if [ "${installed_module_version_major}" -lt "${filebeat_wazuh_module_major}" ] || ([ "${installed_module_version_major}" -eq "${filebeat_wazuh_module_major}" ] && [ "${installed_module_version_minor}" -lt "${filebeat_wazuh_module_minor}" ]); then
      module_upgradable="${filebeat_wazuh_module_version}"
    fi
  fi

  if [ -n "${indexer_installed}" ]; then
    if [ "${sys_type}" == "yum" ]; then
        indexer_upgradable=$(yum list wazuh-indexer --showduplicates | tail -n +8 | grep -A 5000 ${indexer_installed} | tail -n +2 | grep ${wazuh_version})
    elif [ "${sys_type}" == "apt-get" ]; then
        indexer_upgradable=$(apt-get install wazuh-indexer=${wazuh_version}-* --dry-run |grep "The following packages will be upgraded:")
    fi
  fi

  if [ -n "${dashboard_installed}" ]; then
    if [ "${sys_type}" == "yum" ]; then
        dashboard_upgradable=$(yum list wazuh-dashboard --showduplicates | tail -n +8 | grep -A 5000 ${wazuh_installed} | tail -n +2 | grep ${wazuh_version})
    elif [ "${sys_type}" == "apt-get" ]; then
        dashboard_upgradable=$(apt-get install wazuh-dashboard=${wazuh_version}-* --dry-run |grep "The following packages will be upgraded:")
    fi
  fi

}


function upgrade_upgradeInstalled(){

  common_logger "--- Upgrading existing Wazuh installation ---"
  
  upgrade_getUpgradable

  if [ -n "${wazuh_installed}" ]; then
    if [ -n "${manager_upgradable}" ]; then
      common_logger "Upgrading Wazuh Manager to ${wazuh_version}"
      eval "manager_install ${debug}"
      installCommon_startService "wazuh-manager"
    else
      common_logger -w "Wazuh manager is already installed and the version is equal or greater than ${wazuh_version}."
    fi
  fi

  if [ -n "${filebeat_installed}" ]; then
    if [ -n "${filebeat_upgradable}" ]; then
      common_logger "Upgrading Filebeat to ${filebeat_version}"
      eval "filebeat_install ${debug}"
      installCommon_startService "filebeat"
    else
      common_logger -w "Filebeat is already installed and the version is equal or greater than ${filebeat_version}."
    fi

    if [ -n ${module_upgradable} ];then
      common_logger "Upgrading Filebeat module to ${filebeat_wazuh_module_version}"
      eval "curl -s ${filebeat_wazuh_module} --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"
    fi
  fi

  if [ -n "${indexer_installed}" ]; then
    if [ -n "${indexer_upgradable}" ]; then
      common_logger "Upgrading Wazuh Indexer to ${wazuh_version}"
      indexer_disableShardAllocation
      eval "indexer_install ${debug}"
      indexer_enableShardAllocation
      installCommon_startService "wazuh-indexer"
    else
      common_logger -w "Wazuh Indexer is already installed and the version is equal or greater than ${wazuh_version}."
    fi
  fi

  if [ -n "${dashboard_installed}" ]; then
    if [ -n "${dashboard_upgradable}" ]; then
      common_logger "Upgrading Wazuh Dashboard to ${wazuh_version}"
      eval "dashboard_install ${debug}"
      installCommon_startService "wazuh-dashboard"
    else
      common_logger -w "Wazuh Dashboard is already installed and the version is equal or greater than ${wazuh_version}."
    fi
  fi
  
}
