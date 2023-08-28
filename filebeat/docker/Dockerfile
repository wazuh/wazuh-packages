FROM rockylinux:8.5

# Install all the necessary tools to build the packages
RUN yum clean all && yum update -y
RUN yum install -y \
    curl \
    tar \
    git \
    make \
    autoconf \
    automake \
    python3-devel \
    python3-pip \
    gcc 

RUN curl -so go.tar.gz "https://dl.google.com/go/go1.17.10.linux-amd64.tar.gz" > /dev/null 2>&1 && \
    tar -xzf go.tar.gz > /dev/null 2>&1 && \
    mv go /var/ && \
    rm -f go.tar.gz > /dev/null 2>&1

ENV GOROOT "/var/go"
ENV GOPATH "/var"
ENV PATH "$GOPATH/bin:$GOROOT/bin:$PATH"

RUN git clone https://github.com/magefile/mage && \
    cd mage && \
    go run bootstrap.go

# Add the scripts to build the RPM package
ADD build.sh /usr/local/bin/builder
RUN chmod +x /usr/local/bin/builder

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/builder"]
