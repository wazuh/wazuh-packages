FROM s390x/debian:10

ENV DEBIAN_FRONTEND noninteractive

# Installing necessary packages
RUN apt-get update && apt-get install -y apt-utils

RUN apt-get install -y --force-yes \
    curl gcc make sudo wget expect gnupg perl-base perl \
    build-essential procps gawk libsigsegv2 python3 cmake devscripts

RUN apt-get install checkpolicy fontconfig-config fonts-dejavu-core gdal-data libaec0 libarmadillo9 libarpack2 libaudit-dev libauparse0 libblas3 libcap-ng-dev libcharls2 libdap25 libdapclient6v5 libdapserver7v5 libepsilon1 \
    libfontconfig1 libfreetype6 libfreexl1 libfyba0 libgdal20 libgeos-3.7.1 libgeos-c1v5 libgeotiff2 libgfortran5 libgif7 libhdf4-0-alt libhdf5-103 libimagequant0 libjbig0 libjpeg62-turbo libjson-c3 libkmlbase1 \
    libkmlconvenience1 libkmldom1 libkmlengine1 libkmlregionator1 libkmlxsd1 liblapack3 liblcms2-2 libminizip1 libnetcdf13 libnspr4 libnss3 libodbc1 libogdi3.2 libopenjp2-7 libpng16-16 libpoppler82 libpopt0 \
    libpq5 libproj13 libqhull7 libspatialite7 libsuperlu5 libsz2 libtiff5 liburiparser1 libwebp6 libwebpdemux2 libwebpmux3 libxerces-c3.2 odbcinst odbcinst1debian2 policycoreutils policycoreutils-dev \
    policycoreutils-python-utils poppler-data proj-bin proj-data python3-audit python3-decorator python3-gdal python3-ipy python3-networkx python3-numpy python3-olefile python3-pil python3-scipy python3-selinux \
    python3-semanage python3-sepolgen python3-sepolicy python3-setools python3-yaml selinux-basics selinux-policy-default selinux-policy-dev selinux-utils semodule-utils setools -y

# Add the script to build the Debian package
ADD build.sh /usr/local/bin/build_package
RUN chmod +x /usr/local/bin/build_package

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/build_package"]

