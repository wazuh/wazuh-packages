Wazuh Kibana App package
========================

In this repository, you can find the necessary tools to build a Wazuh Kibana App package.

## Tools needed to build the package

To build a Wazuh Kibana app package you need to install the following tools:
  - `docker`: [installation guide](https://docs.docker.com/install/linux/docker-ce/centos/) for RPM and [installation guide](https://docs.docker.com/install/linux/docker-ce/debian/) for Debian.
- `git`:  [installation guide](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).

## Building Wazuh Kibana app packages

To build a Kibana app package, you need to download this repository and use the `generate_wazuh_app.sh` script. This script will download the source code from the [wazuh/wazuh-kibana-app](https://github.com/wazuh/wazuh-kibana-app) repository, build a Docker image with all the necessary tools to build the app package and run a Docker container from that image that will generate a `.zip` package.

1. Download this repository and go to the wazuhapp directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/wazuhapp
    ```

2. Execute the `generate_wazuh_app.sh` script to build the package. There are multiple parameters to select: which version of the app is going to be built, where is going to be stored in, etc. Here you can see all the different parameters:
    ```shellsession
    $ ./generate_wazuh_app.sh -h

    Usage: ./generate_wazuh_app.sh [OPTIONS]

        -b, --branch <branch>     [Required] Select Git branch or tag e.g. 3.8-6.7 or v3.7.2-6.5.4
        -s, --store <path>        [Optional] Set the destination path of package, by defauly /tmp/wazuh-app.
        -r, --revision <rev>      [Optional] Package revision that append to version e.g. x.x.x-rev
        -c, --checksum <path>     [Optional] Generate checksum
        -h, --help                Show this help.

    ```
    * To build the app package from branch 3.8-6.7, revision myrev and store it in `/wazuh-app` you can use:

            # ./generate_wazuh_app.sh -b 3.8-6.7 -s /wazuh-app -r myrev

3. Once the execution finishes, you will find your `.zip` package in the specified folder or in `/tmp/wazuh-app` if no folder was specified.

## More Packages

- [RPM](/rpms/README.md)
- [Debian](/debs/README.md)
- [macOS](/macos/README.md)
- [AIX](/aix/README.md)
- [OVA](/ova/README.md)
- [KibanaApp](/wazuhapp/README.md)
- [WPK](/wpk/README.md)
- [Solaris](/solaris/README.md)
- [HP-UX](/hpux/README.md)

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com)or join to our Slack channel by filling this [form](https://wazuh.com/community/join-us-on-slack/) to ask questions and participate in discussions.

## License and copyright

WAZUH
Copyright (C) 2016-2019 Wazuh Inc.  (License GPLv2)
