FROM ubuntu:bionic
RUN export DEBIAN_FRONTEND="noninteractive" \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        apt-transport-https \
        ca-certificates \
        cabextract \
        gosu \
        gpg-agent \
        p7zip \
        pulseaudio-utils \
        software-properties-common \
        unzip \
        wget \
        winbind \
        zenity \
        make \
        gcc-mingw-w64 \
        git \
    && rm -rf /var/lib/apt/lists/*
RUN wget https://dl.winehq.org/wine-builds/winehq.key \
    && apt-key add winehq.key \
    && apt-add-repository "deb https://dl.winehq.org/wine-builds/ubuntu/ bionic main" \
    && dpkg --add-architecture i386 \
    && apt-get update \
    && apt-get install -y --install-recommends winehq-stable=4.0.1~bionic \
    && rm -rf /var/lib/apt/lists/* \
    && rm winehq.key
# Download mono and gecko
ARG GECKO_VER
RUN mkdir -p /usr/share/wine/mono /usr/share/wine/gecko \
    && wget https://dl.winehq.org/wine/wine-mono/4.7.5/wine-mono-4.7.5.msi \
        -O /usr/share/wine/mono/wine-mono-4.7.5.msi \
    && wget https://dl.winehq.org/wine/wine-gecko/2.47/wine_gecko-2.47-x86.msi \
        -O /usr/share/wine/gecko/wine_gecko-2.47-x86.msi \
    && wget https://dl.winehq.org/wine/wine-gecko/2.47/wine_gecko-2.47-x86_64.msi \
        -O /usr/share/wine/gecko/wine_gecko-2.47-x86_64.msi
# Download winetricks
RUN wget https://raw.githubusercontent.com/Winetricks/winetricks/master/src/winetricks \
        -O /usr/bin/winetricks \
    && chmod +rx /usr/bin/winetricks
# Create user and take ownership of files
RUN groupadd -g 1010 wineuser \
    && useradd --shell /bin/bash --uid 1010 --gid 1010 --create-home --home-dir /home/wineuser wineuser \
    && chown -R wineuser:wineuser /home/wineuser
VOLUME /home/wineuser
COPY pulse-client.conf /etc/pulse/client.conf
COPY entrypoint.sh /usr/bin/entrypoint
WORKDIR /home/wineuser

ENTRYPOINT ["/usr/bin/entrypoint"]
CMD ["/bin/bash"]