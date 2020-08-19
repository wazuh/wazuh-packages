########################   PARAMETERS  ########################

# version                 ?
# server_address          WAZUH_MANAGER
# manager_port            WAZUH_MANAGER_PORT
# protocol                WAZUH_PROTOCOL
# registration_server     WAZUH_REGISTRATION_SERVER
# registration_port       WAZUH_REGISTRATION_PORT
# registration_password   WAZUH_REGISTRATION_PASSWORD
# keep_alive_interval     WAZUH_KEEP_ALIVE_INTERVAL
# time_reconnect          WAZUH_TIME_RECONNECT
# registration_ca         WAZUH_REGISTRATION_CA
# registration_cert       WAZUH_REGISTRATION_CERTIFICATE
# registration_key        WAZUH_REGISTRATION_KEY
# name                    WAZUH_AGENT_NAME
# group                   WAZUH_AGENT_GROUP

###############################################################


LINUX_SYSTEM="Linux"
MACOS_SYSTEM="Darwin"
SOLARIS_SYSTEM='SunOS'
APT_PACKAGE_MANAGER="apt"
YUM_PACKAGE_MANAGER="yum"
DNF_PACKAGE_MANAGER="dnf"
ZYPPER_PACKAGE_MANAGER="zypper"
WAZUH_REPO_VERSION_URL="https://raw.githubusercontent.com/wazuh/wazuh/master/src/VERSION"
PACKAGE_REVISION="1"

package_manager=""
package_version=""
architecture=""
system_os=""
system_architecture=""
system_kernel_version=""
sources_list_path=""

# ----------------------------------------------------------------------------------------------------------------------


help() {
    echo
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "    -v, --version                [Optional] Select wazuh agent version e.g 4.0.0"
    echo "    -h, --help                   [Optional] Show this help."
    echo
    exit $1
}

# ----------------------------------------------------------------------------------------------------------------------


set_system_info() {
  system_os=$(uname -s 2>/dev/null || echo undefined)
  system_architecture=$(uname -p 2>/dev/null || echo undefined)
  system_kernel_version=$(uname -r 2>/dev/null || echo undefined)


  if [ "${system_os}" == "undefined" ] || [ "${system_architecture}" == "undefined" ] || \
     [ "${system_kernel_version}" == "undefined" ]; then
    echo "Could not detect some system info. os=${system_os}, arch=${system_architecture}, "\
         "kernel_version=${system_kernel_version}"
    exit 1
  fi
}

# ----------------------------------------------------------------------------------------------------------------------


set_package_manager() {
  if [ "${system_os}" == "${LINUX_SYSTEM}" ]; then
    if [ -n "$(command -v zypper)" ]; then
      package_manager=${ZYPPER_PACKAGE_MANAGER}
      sources_list_path="/etc/zypp/repos.d/wazuh.repo"
    elif [ -n "$(command -v dnf)" ]; then
      package_manager=${DNF_PACKAGE_MANAGER}
      sources_list_path="/etc/yum.repos.d/wazuh.repo"
    elif [ -n "$(command -v yum)" ]; then
      package_manager=${YUM_PACKAGE_MANAGER}
      sources_list_path="/etc/yum.repos.d/wazuh.repo"
    elif [ -n "$(command -v apt-get)" ]; then
      package_manager=${APT_PACKAGE_MANAGER}
      sources_list_path="/etc/apt/sources.list.d/wazuh.list"
    fi
  fi
}

# ----------------------------------------------------------------------------------------------------------------------


set_package_version() {
  if [ -z "${package_version}" ]; then
    package_version=$(getLastPackageVersion)
  fi

  package_version=$(echo ${package_version} | sed 's/v//g')
}

# ----------------------------------------------------------------------------------------------------------------------


getLastPackageVersion() {
  curl ${WAZUH_REPO_VERSION_URL}
}

# ----------------------------------------------------------------------------------------------------------------------


checkDependencies() {
  if [ "${package_manager}" == "${APT_PACKAGE_MANAGER}" ];then
    ${APT_PACKAGE_MANAGER} install apt-transport-https lsb-release gnupg2 -y
  fi
}

# ----------------------------------------------------------------------------------------------------------------------


initialize_vars() {
  set_system_info
  set_package_manager
  set_package_version
}

# ----------------------------------------------------------------------------------------------------------------------


addRepository() {
  echo "Adding repository..."
  case "${package_manager}" in
    ${APT_PACKAGE_MANAGER})
      curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
      echo "deb https://packages.wazuh.com/3.x/apt/ stable main" | tee ${sources_list_path}
      $APT_PACKAGE_MANAGER update
    ;;

    ${YUM_PACKAGE_MANAGER} | ${DNF_PACKAGE_MANAGER} | ${ZYPPER_PACKAGE_MANAGER})
      rpm --import http://packages.wazuh.com/key/GPG-KEY-WAZUH
      echo -e ""\
        "[wazuh_repo]\n"\
        "gpgcheck=1\n"\
        "gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\n"\
        "enabled=1\n"\
        "name=Wazuh repository\n"\
        "baseurl=https://packages.wazuh.com/3.x/yum/\n"\
        "protect=1\n" | sed 's/^\s//g' > ${sources_list_path}
    ;;
    *)
      echo "No repository detected"
  esac
}

# ----------------------------------------------------------------------------------------------------------------------


installAgent() {
  case "${system_os}" in

    ${LINUX_SYSTEM})

      addRepository

      case "${package_manager}" in

        ${APT_PACKAGE_MANAGER})
          ${package_manager} install wazuh-agent=${package_version}-${PACKAGE_REVISION} -y
        ;;

        ${YUM_PACKAGE_MANAGER} | ${DNF_PACKAGE_MANAGER}| ${ZYPPER_PACKAGE_MANAGER})
          ${package_manager} install wazuh-agent-${package_version}-${PACKAGE_REVISION} -y
        ;;

        ${ZYPPER_PACKAGE_MANAGER})
          # Zypper will install latest package revision by default
          ${package_manager} install -y wazuh-agent-${package_version}
        ;;

      *)
        echo "Could not install agent due to it has not matched with package manager"
      esac
    ;;

  esac
}

# ----------------------------------------------------------------------------------------------------------------------


main() {
  install="no"
  while [ -n "$1" ]
  do
    case "$1" in
    "-v"|"--version")
        package_version=$2
        shift 2
    ;;
    "-h"|"--help")
        help 0
    ;;
    *)
        help 1
    esac
  done

  initialize_vars
  checkDependencies
  installAgent
}

# ----------------------------------------------------------------------------------------------------------------------


main "$@"
