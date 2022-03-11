FROM archlinux:latest

# Installing necessary packages
RUN pacman --noconfirm -Syu && \
    pacman --noconfirm -S \
    curl gcc make sudo wget expect gnupg perl-base perl fakeroot python brotli \
    automake autoconf libtool gawk libsigsegv nodejs base-devel inetutils cmake \
    lsb-release

RUN useradd -ms /bin/bash user

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]
