#!/bin/bash

# Check the system to differ between DEB and RPM
function check_system() {

    if [ -n "$(command -v yum)" ]; then
        sys_type="rpm"
    elif [ -n "$(command -v apt-get)" ]; then
        sys_type="deb"
    else
        echo "Error: could not detect the system."
        exit 1
    fi

}

function download_packages(){}

function indexer_installation(){}

function manager_installation(){}

function filebeat_installation(){}

function dashboard_installation(){}