Wazuh Solaris11 packages
==================

In this repository, you can find the necessary tools to build a Wazuh package for Solaris 11.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
  - `git`: `pkgutil -i git`.

## Building Solaris11 packages

To build a Solaris 11 package, you need to download this repository and use the `generate_wazuh_packages.sh` script. This script will download the source code from the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository and generate a `.p5p` package.

1. Download this repository and go to the `solaris/solaris11` directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/solaris/solaris11
    ```

2. Execute the `generate_wazuh_packages.sh` script to build the package. Here you can see all the different parameters:
    ```shellsession
    # ./generate_wazuh_packages.sh -h

    Usage: ./generate_wazuh_packages.sh [OPTIONS]

        -b, --branch <branch>               Select Git branch or tag e.g. master.
        -e, --environment                   Install all the packages necessaries to build the pkg package.
        -s, --store  <pkg_directory>        Directory to store the resulting pkg package. By default, an output folder will be created.
        -p, --install-path <pkg_home>       Installation path for the package. By default: /var.
        -c, --checksum                      Compute the SHA512 checksum of the pkg package.
        -h, --help                          Shows this help.
    ```

    * To install the needed dependencies:
        `# ./generate_wazuh_packages.sh -e`.
    * To build a wazuh-agent package from the downloaded v3.9.0 sources:
        `# ./generate_wazuh_packages.sh -b v3.9.0`.

3. When the execution finishes, you can find your `.p5p` in the same directory where the sources are located.

## More Packages

- [RPM](/rpms/README.md)
- [Debian](/debs/README.md)
- [macOS](/macos/README.md)
- [AIX](/aix/README.md)
- [OVA](/ova/README.md)
- [KibanaApp](/wazuhapp/README.md)
- [SplunkApp](/splunkapp/README.md)
- [Solaris](/solaris/README.md)
- [HP-UX](/hpux/README.md)

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com)or join to our Slack channel by filling this [form](https://wazuh.com/community/join-us-on-slack/) to ask questions and participate in discussions.

## License and copyright

WAZUH
Copyright (C) 2016-2019 Wazuh Inc.  (License GPLv2)