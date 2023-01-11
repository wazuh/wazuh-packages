FROM centos:7

RUN rpm -Uvh https://yum.puppet.com/puppet-tools-release-el-7.noarch.rpm && yum install pdk

# Create the build directory and add file
ADD build.sh /
RUN chmod +x /build.sh

# Set the entrypoint/
ENTRYPOINT ["/build.sh"]