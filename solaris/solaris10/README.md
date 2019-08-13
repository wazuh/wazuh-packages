Wazuh Solaris10 packages
==================

In this repository, you can find the necessary tools to build a Wazuh package for Solaris 10.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
  - `git`: `pkgutil -i git`.

## Building Solaris10 packages

To build a Solaris 10 package, you need to download this repository and use the `generate_wazuh_packages.sh` script. This script will download the source code from the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository and generate a `.pkg` package.

1. Download this repository and go to the `solaris/solaris10` directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/solaris/solaris10
    ```

2. Execute the `generate_wazuh_packages.sh` script to build the package. Here you can see all the different parameters:
    ```shellsession
    # ./generate_wazuh_packages.sh -h

    Usage: ./generate_wazuh_packages.sh [OPTIONS]

    USAGE: Command line arguments available:
        -h, --help               Displays this help.
        -d, --download           Download source file and prepares source directories.
        -u, --utils              Download and install all dependencies.
        -b, --build              Build Solaris 10 packages.
        -c, --clean              Clean all. Even installation files.
    ```

    * To install the needed dependencies:
        `# ./generate_wazuh_packages.sh -u`.
    * To download the sources from tag v3.9.0:
        `# ./generate_wazuh_packages.sh -d v3.9.0`.
    * To build a wazuh-agent package from the downloaded v3.9.0 sources:
        `# ./generate_wazuh_packages.sh -b v3.9.0`.

3. When the execution finishes, you can find your `.pkg` in the same directory where the sources are located.

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
