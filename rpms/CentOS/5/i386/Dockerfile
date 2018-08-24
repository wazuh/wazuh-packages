FROM i386/centos:5.11

# Add the repositories
COPY CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo
RUN yum update -y && yum clean all

# Install sudo, SSH and compilers
RUN yum install -y sudo ca-certificates openssh-server \
    make gcc curl openssh-clients initscripts tar \
    rpm-build gnupg automake autoconf libtool wget

RUN yum groupinstall -y "Development tools"
RUN yum install -y  zlib-devel bzip2-devel openssl-devel ncurses-devel
# Install Perl 5.10
RUN wget http://www.cpan.org/src/5.0/perl-5.10.1.tar.gz
RUN gunzip perl-5.10.1.tar.gz
RUN tar -xvf perl*.tar

WORKDIR /perl-5.10.1
RUN ./Configure -des -Dcc='gcc'
RUN make && make install
RUN ln -fs /usr/local/bin/perl /bin/perl

WORKDIR /

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Create the build directory
RUN mkdir /build_wazuh
ADD wazuh.spec /build_wazuh/wazuh.spec

# Add the volumes
VOLUME /var/local/wazuh
VOLUME /etc/wazuh

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
