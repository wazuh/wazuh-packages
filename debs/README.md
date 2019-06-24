Wazuh DEB packages
==================

In this repository, you can find the necessary tools to build a Wazuh package for Debian based OS.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
  - `docker`: [installation guide](https://docs.docker.com/install/linux/docker-ce/debian/).
  - `git`: `apt-get install git`.

## Building DEB packages

Building a .deb package is pretty similar to build a .rpm package. You need to download the repository and execute the `generate_debian_package.sh` script. This will create the docker image, choose the needed files to build the package and build it.

1. Download this repository and go to the debs directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/debs
    ```

2. Execute the `generate_debian_package.sh` script to built the package. There are multiple parameters to select which package is going to be build, its architecture, etc. Here you can see all the different parameters:
      ```shellsession
      # ./generate_debian_package.sh -h

      Usage: ./generate_debian_package.sh [OPTIONS]

          -b, --branch <branch>     [Required] Select Git branch or tag e.g.
          -s, --store <path>        [Optional] Set the destination path of package.
          -t, --target <target>     [Required] Target package to build [manager/api/agent].
          -a, --architecture <arch> [Optional] Target architecture of the package [amd64/i386].
          -r, --revision <rev>      [Optional] Package revision that append to version e.g. x.x.x-rev
          -j, --jobs <number>       [Optional] Number of parallel jobs when compiling.
          -p, --path <path>         [Optional] Installation path for the package. By default: /var/ossec.
          -d, --debug               [Optional] Build the binaries with debug symbols. By default: no.
          -h, --help                Show this help.

      ```
    * To build a wazuh-manager package for amd64 (x86_64) and store it in `/tmp`:
        `# ./generate_debian_package.sh -b 3.9 -s /tmp -t manager -a amd64 -r 0`.
    * To build a wazuh-agent package in `/home/user` for i386 with release 2:
        `# ./generate_debian_package.sh -b v3.8.2 -s /home/user -t agent -a i386 -r 2`.
    * To build a wazuh-api package from branch 3.9 and store it in `/tmp`:
        `# ./generate_debian_package.sh -b 3.9 -s /tmp -t api -a amd64 -r 0`.
    * To build a wazuh-manager amd64 (x86_64) package for `/opt/ossec` directory and store it in `/tmp`:
        `# ./generate_debian_package.sh -b 3.9 -s /tmp -t manager -a amd64 -r 0 -p /opt/ossec`.
3. When the execution finishes, you can find your `.deb` packages in specified folder.

## More Packages

- [RPM](/rpms/README.md)
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
