Wazuh RPM packages for IBM AIX
==============================

In this repository, you can find the necessary tools to build a Wazuh package for AIX.

## Building RPM packages

To build an AIX package, you need to download this repository and use the `generate_wazuh_packages.sh` script. This script will download the source code from the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository, and generate the `.ppc.rpm` package. In addition, you can install the build dependencies with this script.

1. Download this repository and go to the rpm directory:
    ```bash
    $ curl -L https://github.com/wazuh/wazuh-packages/tarball/master | tar zx
    $ cd wazuh-wazuh-packages-*
    $ cd aix
    ```

2. Execute the `generate_wazuh_packages.sh` script to build the package. There are multiple parameters to select which package is going to be built, its architecture, etc. Here you can see all the different parameters:
    ```shellsession
    # ./generate_wazuh_packages.sh -h

    Usage: ./generate_wazuh_packages.sh [OPTIONS]

        -b, --branch <branch>               Select Git branch or tag e.g.
        -e, --environment                   Install all the packages necessaries to build the RPM package
        -s, --store  <rpm_directory>        Directory to store the resulting RPM package. By default: /tmp/build
        -p, --install-path <rpm_home>       Installation path for the package. By default: /var
        -c, --checksum                      Compute the SHA512 checksum of the RPM package.
        -h, --help                          Shows this help
    ```
    * To install all the dependencies necessaries to build the RPM package:

        `# ./generate_wazuh_packages.sh -e`
    * To build a wazuh-agent package for version 3.8.2, revision 3821 and store it in `/tmp`:

        `# ./generate_wazuh_packages.sh -b v3.8.2 -s /tmp -a x86_64 -r 3821`.
    * To install the dependencies, build a wazuh-agent package for version 3.8.2, revision 3821 and store it in `/tmp`:

        `# ./generate_wazuh_packages.sh -b v3.8.2 -s /tmp -a x86_64 -r 3821`.

3. When the execution finishes, you can find your `.ppc.rpm` package in specified folder.

## More Packages

- [RPM](/rpms/README.md)
- [Debian](/debs/README.md)
- [macOS](/macos/README.md)
- [OVA](/ova/README.md)
- [KibanaApp](/wazuhapp/README.md)
- [SplunkApp](/splunkapp/README.md)
- [WPK](/wpk/README.md)
- [Solaris](/solaris/README.md)
- [HP-UX](/hpux/README.md)

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com)or join to our Slack channel by filling this [form](https://wazuh.com/community/join-us-on-slack/) to ask questions and participate in discussions.

## License and copyright

WAZUH
Copyright (C) 2016-2019 Wazuh Inc.  (License GPLv2)
