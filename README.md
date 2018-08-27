Wazuh
=====

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://goo.gl/forms/M2AoZC4b2R9A9Zy12)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

Wazuh is an Open Source Host-based Intrusion Detection System that performs log analysis, file integrity monitoring, policy monitoring, rootkit detection, real-time alerting, active response, vulnerability detector, etc.

In this repository, you can find the necessary tools to build a Wazuh package for Debian based OS (.deb) and an RPM based OS package (.rpm).

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
  - `docker`: [installation guide](https://docs.docker.com/install/linux/docker-ce/centos/) for RPM and [installation guide](https://docs.docker.com/install/linux/docker-ce/debian/) for Debian.
  - `git`: `apt-get install git` for Debian based OS or `yum install git` for RPM based OS.
  
## Building RPM packages

To build an RPM package, you need to download this repository and use the `generate_wazuh_rpm.sh` script. This script will download the source code from the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository or the [wazuh/wazuh-api](https://github.com/wazuh/wazuh-api) (depending on which package do you want to build), select automatically the RPM spec file, build a Docker image with all the necessary tools to build the RPM package and run a Docker container from that image that will generate the `.src.rpm` and `.rpm` packages. These packages will be stored by default in `$HOME/3.x/yum-dev`.

1. Download this repository and go to the rpm directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/rpms
    ```

2. Execute the `generate_wazuh_rpm.sh` script to build the package. There are multiple parameters to select which package is going to be built, its architecture, etc. Here you can see all the different parameters:
    ```shellsession
    # ./generate_wazuh_rpm.sh -h

    Usage: ./generate_wazuh_rpm.sh [OPTIONS]

        -b, --branch <branch>     Select Git branch [master].
        -h, --help                Show this help.
        -t, --target              Target package to build: manager, api or agent.
        -a, --architecture        Target architecture of the package.
        -j, --jobs                Change number of parallel jobs when compiling the manager or agent.
        -l, --legacy              Build the package for CentOS 5.
        -r, --release             Package release.
        -p, --path                Installation path for the package. By default: /var.
    ```
    * To build a wazuh-manager package for x86_64:  
        `# ./generate_wazuh_rpm.sh -b v3.4.0 -t manager -a x86_64`.
    * To build a wazuh-agent package for i386 with `-j15` and release 3:  
        `# ./generate_wazuh_rpm.sh -b v3.4.0 -t agent -a x86_64 -j 15 -r 3`.
    * To build a wazuh-api package from branch 3.6:  
        `# ./generate_wazuh_rpm.sh -b 3.6 -t api`.
    * To build a wazuh-manager package for x86_64 in a different directory:  
        `# ./generate_wazuh_rpm.sh -b v3.4.0 -t manager -a x86_64 -p /opt`.
3. When the execution finish, you can find your `.src.rpm` and the `.rpm` packages in `$HOME/3.x/yum-dev`.


## Building DEB packages

Building a .deb package is pretty similar to build a .rpm package. You need to download the repository and execute the `generate_wazuh_debs.sh` script. This will create the docker image, choose the needed files to build the package and build it. These packages will be stored by default in `$HOME/3.x/apt-dev`.

1. Download this repository and go to the debs directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/debs
    ```

2. Execute the `generate_wazuh_debs.sh` script to built the package. There are multiple parameters to select which package is going to be build, its architecture, etc. Here you can see all the different parameters:
      ```shellsession
      # ./generate_wazuh_debs.sh -h

      Usage: ./generate_wazuh_debs.sh [OPTIONS]
    
        -b, --branch <branch>     Select Git branch or tag [master].
        -h, --help                Show this help.
        -t, --target              Target package to build: manager, api or agent.
        -a, --architecture        Target architecture of the package.
        -j, --jobs                Change number of parallel jobs when compiling the manager or agent.
        -r, --revision            Package revision.
        -p, --path                Installation path for the package. By default: /var/ossec.
      ```
    * To build a wazuh-manager package for amd64 (x86_64):  
        `# ./generate_wazuh_debs.sh -b 3.4 -t manager`.
    * To build a wazuh-agent package for i386 with release 2:  
        `# ./generate_wazuh_debs.sh -b v3.5.0 -t agent -a i386 -r 2`.
    * To build a wazuh-api package from branch 3.6:  
        `# ./generate_wazuh_debs.sh -b 3.6 -t api`.
    * To build a wazuh-manager package for amd64 (x86_64) in a different directory:  
        `# ./generate_wazuh_debs.sh -b 3.4 -t manager -p /opt/ossec`.
3. When the execution finish, you can find your `.deb` packages in `$HOME/3.x/apt-dev`.

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh), by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com), to ask questions and participate in discussions.

## License and copyright

WAZUH  
Copyright (C) 2016-2018 Wazuh Inc.  (License GPLv2)
