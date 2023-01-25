#!/bin/sh

scriptpath=$(dirname "$0")
. /etc/os-release
if [ "$ID" = "alpine" ]; then
    sh $scriptpath/setup_docker_alpine.sh
elif [ "$ID" = "ubuntu" ]; then
    bash $scriptpath/setup_docker_ubuntu.sh
fi