#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd ../"$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/tests/bach.sh


# test-example() {
#     @mock ls -la === false
#     ls -la 
#     $?=1
#     if [ "$?" != 0 ]; then
#         exit 1
#     fi
#     echo $?
# }

# # test-example-assert() {
# #     @echo Hello World
# # }

# test-configureWazuhCluster() {
#     load-configureWazuhCluster
#     wazuh_servers_node_names=( wazuh1 wazuh2 wazuh3 )
#     wazuh_servers_node_types=( master agent agent )
#     wazuh_servers_node_ips=( 192.168.20.20 192.168.20.30 192.168.20.40 )
#     winame=wazuh2
#     tar_file=/tmp/tarfile.tar
#     @mock tar -axf "${tar_file}" ./clusterkey -O === @out a9979b2ef643a9e8f3419159ab0670f0
#     configureWazuhCluster
#     @echo $pos
#     @echo $master_address
#     @echo $key
# }

test-false() {
     @mockfalse foo
     if [ x = x ]; then
         foo
     else
         bar
     fi
     if [ "$?" != 0 ]; then
         exit 1
     fi
     echo done
}

test-false-assert() {
    @false
}

test-true() {
    @mockfalse foo
    if [ y = x ]; then
        foo
    else
        bar
    fi
    if [ "$?" != 0 ]; then
        exit 1
    fi
    echo done
}

test-true-assert() {
    bar
    echo done
}