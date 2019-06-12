# Wazuh package builder
# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Script parameters to build the package
wazuh_version=$1
revision=$2
msi_name="wazuh-agent-${wazuh_version}-${revision}"

download_sources(){
    git clone https://github.com/wazuh/wazuh.git
    git checkout ${wazuh_version}
}

download_wix_binaries(){
    wget https://github.com/wixtoolset/wix3/releases/download/wix3111rtm/wix311exe.zip
    unzip wix311exe.zip wix
}

compile(){
    make TARGET=winagent
}

build_msi(){
    wine wix/candle.exe -ext "wix/WixUtilExtension.dll" wazuh-installer.wxs
    wine wix/light.exe -ext "wix/WixUtilExtension.dll" -ext "wix/WixUIExtension.dll" -out ${msi_name}  -sval wazuh-installer.wixobj
}

main(){
    download_sources()
    cd wazuh/src
    compile()
    cd win32
    download_wix_binaries()
    mv ${msi_name} ${destination}
}

main()


# Build directories
