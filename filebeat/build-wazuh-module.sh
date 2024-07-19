#!/usr/bin/env bash
set -x
: '
Wazuh, Inc. (c) 2019

Extra requirements:
 python-virtualenv, gcc, make, docker

Usage:
 chmod a+x ./build-filebeat-module.sh
 ./build-filebeat-module.sh

How it works:
 It prepares a Beats dev environment, configures Go and builds the Wazuh module.
 The result is found at /tmp/wazuh.tar.gz

Content:
 wazuh
 ├── alerts
 │   ├── config
 │   │   └── alerts.yml
 │   ├── ingest
 │   │   └── pipeline.json
 │   └── manifest.yml
 ├── archives
 │   ├── config
 │   │   └── archives.yml
 │   ├── ingest
 │   │   └── pipeline.json
 │   └── manifest.yml
 └── module.yml
'

# Edit these env variables at your own
W_BASE_DIR="/tmp/filebeat-wazuh"
W_BEATS_BRANCH="v7.10.2"
W_WAZUH_BRANCH="4.3"
W_FILENAME="wazuh-filebeat-0.2.tar.gz"
GO_VERSION="1.17.10"

# Clean previous building attempts
rm -rf $W_BASE_DIR
rm -rf /tmp/go
rm -rf /tmp/wazuh

# Prepare Go environment
echo "Installing Go..."

curl -so go.tar.gz "https://dl.google.com/go/go$GO_VERSION.linux-amd64.tar.gz" > /dev/null 2>&1
tar -xzf go.tar.gz > /dev/null 2>&1
mv go /tmp/
rm -f go.tar.gz > /dev/null 2>&1
mkdir $W_BASE_DIR
cd $W_BASE_DIR

# Go environment variables
export GOROOT=/tmp/go
export GOPATH=$W_BASE_DIR
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
go version

git clone https://github.com/magefile/mage > /dev/null 2>&1
cd mage > /dev/null 2>&1
go run bootstrap.go > /dev/null 2>&1
cd $W_BASE_DIR

# Download Bgo get github.com/elastic/beatseats repository, needed for building Filebeat modules
git clone https://github.com/elastic/beats.git -b $W_BEATS_BRANCH --single-branch --depth=1  > /dev/null 2>&1
cd beats/filebeat/ > /dev/null 2>&1
git checkout $W_BEATS_BRANCH > /dev/null 2>&1
go get > /dev/null 2>&1
make
make create-module MODULE=wazuh
rm -rf module/wazuh/*

# Fetch Wazuh module source files
cd /tmp
git clone https://github.com/wazuh/wazuh -b $W_WAZUH_BRANCH --single-branch --depth=1 > /dev/null 2>&1
cd $W_BASE_DIR/beats/filebeat/
cp -R /tmp/wazuh/extensions/filebeat/7.x/wazuh-module/* module/wazuh
rm -rf /tmp/wazuh

# Generate production files for Wazuh module
make update 
cd build/package/module
sudo chown root:root -R wazuh/
tar -czvf $W_FILENAME wazuh/* > /dev/null 2>&1

# Move final package to /tmp/$W_FILENAME
mv $W_BASE_DIR/beats/filebeat/build/package/module/$W_FILENAME /tmp

# # Optional. Upload the module to Amazon S3
# S3_PATH="packages-dev.wazuh.com/3.x/filebeat"
# S3_FILENAME="wazuh-filebeat-0.1.tar.gz"
# cd /tmp
# aws s3 cp /tmp/"$W_FILENAME" s3://"$S3_PATH/$W_FILENAME" --acl public-read

exit 0
