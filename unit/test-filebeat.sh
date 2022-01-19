#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore logger
}

function load-copyCertificatesFilebeat() {
    @load_function "${base_dir}/filebeat.sh" copyCertificatesFilebeat
}