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
        manager_upgradable=$(yum check-update wazuh-manager | grep wazuh-manager | sed 's/  */ /g'| cut -d' ' -f2 | sed "s/-.*//g")
    elif [ "${sys_type}" == "apt-get" ]; then
        manager_upgradable=$(apt list wazuh-manager -a 2>/dev/null | grep "upgradable from" | cut -d' ' -f2 | sed -e "s/-.*//")
    fi
  fi

  if [ -n "${filebeat_installed}" ]; then
    if [ "${sys_type}" == "yum" ]; then
        filebeat_upgradable=$(yum check-update filebeat | grep filebeat | sed 's/  */ /g'| cut -d' ' -f2 | sed "s/-.*//g")
    elif [ "${sys_type}" == "apt-get" ]; then
        filebeat_upgradable=$(apt list filebeat -a 2>/dev/null | grep "upgradable from" | cut -d' ' -f2 | sed -e "s/-.*//")
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
        indexer_upgradable=$(yum check-update wazuh-indexer | grep wazuh-indexer | sed 's/  */ /g'| cut -d' ' -f2 | sed "s/-.*//g")
    elif [ "${sys_type}" == "apt-get" ]; then
        indexer_upgradable=$(apt list wazuh-indexer -a 2>/dev/null | grep "upgradable from" | cut -d' ' -f2 | sed -e "s/-.*//")
    fi
  fi

  if [ -n "${dashboard_installed}" ]; then
    if [ "${sys_type}" == "yum" ]; then
        dashboard_upgradable=$(yum check-update wazuh-dashboard | grep wazuh-dashboard | sed 's/  */ /g'| cut -d' ' -f2 | sed "s/-.*//g")
    elif [ "${sys_type}" == "apt-get" ]; then
        dashboard_upgradable=$(apt list wazuh-dashboard -a 2>/dev/null | grep "upgradable from" | cut -d' ' -f2 | sed -e "s/-.*//")
    fi
  fi

}


function upgrade_upgradeInstalled(){

  common_logger "--- Upgrading existing Wazuh installation ---"
  
  upgrade_getUpgradable

  if [ -n "${wazuh_installed}" ]; then
    if [ -n "${manager_upgradable}" ]; then
      if [ "${manager_upgradable}" == "${wazuh_version}" ]; then
        common_logger "Upgrading Wazuh Manager to ${manager_upgradable}"
        eval "manager_install ${debug}"
      else
        common_logger -w "Wazuh manager can be upgraded but the version does not match the installation assistant version"
      fi
    else
      common_logger -w "Wazuh manager is already installed and is up to date."
    fi
  fi

  if [ -n "${filebeat_installed}" ]; then
    if [ -n "${filebeat_upgradable}" ]; then
      if [ "${filebeat_upgradable}" == "${filebeat_version}" ]; then
        common_logger "Upgrading Filebeat to ${filebeat_upgradable}"
        eval "filebeat_install ${debug}"
      else
        common_logger -w "Filebeat can be upgraded but the version does not match the installation assistant version"
      fi
    else
      common_logger -w "Filebeat is already installed and is up to date."
    fi

    if [ -n ${module_upgradable} ];then
      common_logger "Upgrading Filebeat module to ${filebeat_wazuh_module_version}"
      eval "curl -s ${filebeat_wazuh_module} --max-time 300 | tar -xvz -C /usr/share/filebeat/module ${debug}"
    fi
  fi

  if [ -n "${indexer_installed}" ]; then
    if [ -n "${indexer_upgradable}" ]; then
      if [ "${indexer_upgradable}" == "${wazuh_version}" ]; then
        common_logger "Upgrading Wazuh Indexer to ${indexer_upgradable}"
        eval "indexer_install ${debug}"
      else
        common_logger -w "Wazuh Indexer can be upgraded but the version does not match the installation assistant version"
      fi
    else
      common_logger -w "Wazuh Indexer is already installed and is up to date."
    fi
  fi

  if [ -n "${dashboard_installed}" ]; then
    if [ -n "${dashboard_upgradable}" ]; then
      if [ "${dashboard_upgradable}" == "${wazuh_version}" ]; then
        common_logger "Upgrading Wazuh Dashboard to ${dashboard_upgradable}"
        eval "dashboard_install ${debug}"
      else
        common_logger -w "Wazuh Dashboard can be upgraded but the version does not match the installation assistant version"
      fi
    else
      common_logger -w "Wazuh Dashboard is already installed and is up to date."
    fi
  fi
  
}
