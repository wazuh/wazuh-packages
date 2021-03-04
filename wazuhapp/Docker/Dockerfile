FROM centos:7

# Create the build directory and add file
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7 && \
    curl -sL https://rpm.nodesource.com/setup_10.x | bash - && \
    yum install git nodejs gcc gcc-c++ make sudo -y && \
    npm install -g n 

# Configure non-root user
RUN useradd -ms /bin/bash builduser
RUN usermod -aG wheel builduser
RUN echo "%wheel	ALL=(ALL)	NOPASSWD: ALL" >> /etc/sudoers

ADD build.sh /home/builduser
RUN chmod +x /home/builduser/build.sh
RUN chown builduser:builduser /home/builduser/build.sh

USER builduser
WORKDIR /home/builduser

# Add the volumes
RUN mkdir wazuh_app source

# Set the entrypoint/
ENTRYPOINT ["/home/builduser/build.sh"]
