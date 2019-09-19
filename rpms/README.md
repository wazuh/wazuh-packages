Wazuh RPM packages
==================

In this repository, you can find the necessary tools to build a Wazuh package for RPM based OS.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
  - `docker`: [installation guide](https://docs.docker.com/install/linux/docker-ce/centos/).
  - `git`: `yum install git`.

## Building RPM packages

To build an RPM package, you need to download this repository and use the `generate_rpm_package.sh` script. This script will download the source code from the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository or the [wazuh/wazuh-api](https://github.com/wazuh/wazuh-api) (depending on which package do you want to build), select automatically the RPM spec file, build a Docker image with all the necessary tools to build the RPM package and run a Docker container from that image that will generate the `.src.rpm` and `.rpm` packages.

1. Download this repository and go to the rpm directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/rpms
    ```

2. Execute the `generate_rpm_package.sh` script to build the package. There are multiple parameters to select which package is going to be built, its architecture, etc. Here you can see all the different parameters:
    ```shellsession
    #  ./generate_rpm_package.sh -h

    Usage: ./generate_rpm_package.sh [OPTIONS]

        -b, --branch <branch>     [Required] Select Git branch or tag e.g. master
        -t, --target <target>     [Required] Target package to build [manager/api/agent].
        -a, --architecture <arch> [Optional] Target architecture of the package [x86_64/i386].
        -r, --revision <rev>      [Optional] Package revision that append to version e.g. x.x.x-rev
        -l, --legacy              [Optional] Build package for CentOS 5.
        -s, --store <path>        [Optional] Set the destination path of package.
        -j, --jobs <number>       [Optional] Number of parallel jobs when compiling.
        -p, --path <path>         [Optional] Installation path for the package. By default: /var.
        -d, --debug               [Optional] Build the binaries with debug symbols and create debuginfo packages. By default: no.
        -c, --checksum <path>     [Optional] Generate checksum on the desired path (by default, if no path is specified it will be generated on the same directory than the package).
        -h, --help                Show this help.
    ```
    * To build a wazuh-manager package for x86_64, revision 3821 and store it in `/tmp`:
        `# ./generate_rpm_package.sh -b v3.8.2 -s /tmp -t manager -a x86_64 -r 3821`.
    * To build a wazuh-agent package for i386 with `-j15`, revision 3 and store it in `/tmp`:
        `# ./generate_rpm_package.sh -b v3.8.2 -s /tmp -t agent -a x86_64 -j 15 -r 3`.
    * To build a wazuh-api package from branch 3.9 and store it in `/tmp`:
        `# ./generate_rpm_package.sh -b 3.9 -s /tmp -t api -a x86_64 -r 0`.
    * To build a wazuh-manager x86_64 package for `/opt/ossec` directory and store it in `/tmp`:
        `# ./generate_rpm_package.sh -b v3.8.2 -s /tmp -t manager -a x86_64 -r 0.1 -p /opt`.

    If you build a package using `-d` parameter, you need to install the `wazuh-xxxxx` and the `wazuh-xxxxx-debuginfo` package in order to install the debugging symbols of the package if you want to debug the binaries using `gdb` for example.

3. When the execution finishes, you can find your `.src.rpm` and the `.rpm` packages in specified folder.

## More Packages

- [Debian](/debs/README.md)
- [macOS](/macos/README.md)
- [AIX](/aix/README.md)
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
