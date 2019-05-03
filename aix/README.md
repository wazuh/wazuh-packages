Wazuh
=====

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

Wazuh is an Open Source Host-based Intrusion Detection System that performs log analysis, file integrity monitoring, policy monitoring, rootkit detection, real-time alerting, active response, vulnerability detector, etc.

In this repository, you can find the necessary tools to build a Wazuh package for AIX.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
  - `git` : `yum install git`.

## Building RPM packages

To build an AIX package, you need to download this repository and use the `generate_wazuh_rpm.sh` script. This script will download the source code from the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository, and generate the `.ppc.rpm` package.

1. Download this repository and go to the rpm directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/aix
    ```

2. Execute the `generate_rpm_package.sh` script to build the package. There are multiple parameters to select which package is going to be built, its architecture, etc. Here you can see all the different parameters:
    ```shellsession
    #./generate_package.sh -h

    Usage: ./generate_rpm.sh [OPTIONS]

        Usage: $0 [OPTIONS]"
  
            -e Install all the packages necessaries to build the RPM package"
            -b <branch> Select Git branch. Example v3.5.0"
            -s <rpm_directory> Directory to store the resulting RPM package. By default: /tmp/build"
            -p <rpm_home> Installation path for the package. By default: /var"
            -h Shows this help"
    ```
    * To install all the dependencies necessaries to build the RPM package:

        `# ./generate_package.sh -e`
    * To build a wazuh-agent package for version 3.8.2, revision 3821 and store it in `/tmp`:

        `# ./generate_package.sh -b v3.8.2 -s /tmp -a x86_64 -r 3821`.
    * To install the dependencies, build a wazuh-agent package for version 3.8.2, revision 3821 and store it in `/tmp`:

        `# ./generate_package.sh -b v3.8.2 -s /tmp -a x86_64 -r 3821`.
    
3. When the execution finishes, you can find your `.ppc.rpm` package in specified folder.

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com) to ask questions and participate in discussions.

## License and copyright

WAZUH
Copyright (C) 2016-2019 Wazuh Inc.  (License GPLv2)
