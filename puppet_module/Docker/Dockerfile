FROM centos:7

RUN rpm -Uvh https://yum.puppet.com/puppet-tools-release-el-7.noarch.rpm && yum install -y pdk

RUN pdk set config user.analytics.disabled false --type boolean --force

# Create the build directory and add file
ADD build.sh /
RUN chmod +x /build.sh

# Set the entrypoint/
ENTRYPOINT ["/build.sh"]
