Wazuh
=====

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

Wazuh is an Open Source Host-based Intrusion Detection System that performs log analysis, file integrity monitoring, policy monitoring, rootkit detection, real-time alerting, active response, vulnerability detector, etc.

In this repository, you can find the necessary tools to build a Wazuh Splunk app package.

## Tools needed to build the package

To build a Wazuh Splunk app package you need to install the following tools:
  - `docker`: [installation guide](https://docs.docker.com/install/linux/docker-ce/centos/) for RPM and [installation guide](https://docs.docker.com/install/linux/docker-ce/debian/) for Debian.
- `git`:  [installation guide](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git). 
  
## Building Wazuh Splunk app packages

To build a Splunk app package, you need to download this repository and use the `generate_wazuh_splunk_app.sh` script. This script will download the source code from the [wazuh/wazuh-splunk](https://github.com/wazuh/wazuh-splunk) repository build a Docker image with all the necessary tools to build the app package and run a Docker container from that image that will generate a `.tar.gz` package.

1. Download this repository and go to the splunkapp directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-installers && cd wazuh-installers/splunkapp
    ```

2. Execute the `generate_wazuh_splunk_app.sh` script to build the package. There are multiple parameters to select: which version of the app is going to be built, where is going to be stored in, etc. Here you can see all the different parameters:
    ```shellsession
    $./generate_wazuh_splunk_app.sh -h

    Usage: generate_wazuh_splunk_app.sh [OPTIONS]

        -b, --branch <branch>     [Required] Select Git branch or tag e.g. 3.8 or v3.8.1-7.2.3
        -s, --store <directory>   [Optional] Destination directory by default /tmp/splunk-app
        -r, --revision            [Optional] Package revision that append to version e.g. x.x.x-y.y.y-rev
        -h, --help                Show this help.
                    
    ```
    * To build the app package for version 3.8.2, using Splunk with version 7.2.3, revision myrev and store it in `/splunk-app` you can either use:

            # ./generate_wazuh_splunk_app.sh -b v3.8.1-7.2.3 -d /splunk-app -r myrev.
            # ./generate_wazuh_splunk_app.sh -b 3.8.2 -d /splunk-app -r no -sp 7.2.3
    * If no Splunk version is indicated the package generated will contain the latest version of the app for a given branch.

            # ./generate_wazuh_splunk_app.sh -b 3.8 -d /splunk-app -r myrev
        
3. Once the execution finishes, you will find your `.taz.gz` package in the specified folder or in /tmp/splunk-app if no folder was specified.

## More Packages

- [RPM](/rpms/README.md)
- [Debian](/debs/README.md)
- [MacOS](/macos/README.md)
- [AIX](/aix/README.md)
- [OVA](/splunkapp/README.md)
- [KibanaApp](/wazuhapp/README.md)

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com) to ask questions and participate in discussions.

## License and copyright

WAZUH
Copyright (C) 2016-2019 Wazuh Inc.  (License GPLv2)
