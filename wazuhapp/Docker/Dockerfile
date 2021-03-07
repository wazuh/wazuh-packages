FROM centos:8

# Docker image arguments
ARG USER=builduser
ARG UID=1000
ARG GID=1000

# Install dependencies
RUN rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-centostesting && \
    curl -sL https://rpm.nodesource.com/setup_10.x | bash - && \
    yum install nodejs git gcc gcc-c++ make sudo zip python3 -y && \
    alternatives --set python /usr/bin/python3 && \
    npm install -g n 

# Configure non-root user
RUN useradd -ms /bin/bash ${USER} && \
    usermod -aG wheel ${USER} && \
    echo "%wheel	ALL=(ALL)	NOPASSWD: ALL" >> /etc/sudoers

# Create the build directory and add file
ADD build.sh /home/${USER}
RUN chmod +x /home/${USER}/build.sh && \
    chown ${USER}:${USER} /home/${USER}/build.sh

USER ${UID}:${GID}
WORKDIR /home/${USER}

# Add the volumes
RUN mkdir wazuh_app source

# Set the entrypoint/
ENTRYPOINT ["./build.sh"]
