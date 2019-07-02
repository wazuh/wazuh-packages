Wazuh macOS packages
====================

In this repository, you can find the necessary tools to build a Wazuh package for macOS.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
- [Packages](http://s.sudre.free.fr/Software/Packages/about.html): You can install this on macOS using the `generate_wazuh_packages.sh` script in this repo.
- [brew](https://brew.sh/): You can install this on macOS using the `generate_wazuh_packages.sh` script in this repo.
- `git`: on macOS install with homebrew use `brew install git`

## Building macOS packages

To build an macOS package, you need to download this repository and use the `generate_wazuh_packages.sh` script. This script will download the source code from the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository and automatize the package generation.

1. Download this repository and go to the rpm directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/macos
    ```

2. Execute the `generate_wazuh_packages.sh` script to build the package. There are multiple parameters for selecting which package is going to be built, such as install destination, etc. Also you can install `Packages` using the script. Here you can see all the different parameters:
    ```shellsession
    $ ./generate_wazuh_packages.sh -h

    Usage: $0 [OPTIONS]
        -b, --branch <branch>     [Required] Select Git branch or tag e.g. $BRANCH"
        -s, --store-path <path>   [Optional] Set the destination absolute path of package."
        -j, --jobs <number>       [Optional] Number of parallel jobs when compiling."
        -r, --revision <rev>      [Optional] Package revision that append to version e.g. x.x.x-rev"
        -h, --help                [  Util  ] Show this help."
        -i, --install-deps        [  Util  ] Install build dependencies (Packages)."
        -x, --install-xcode       [  Util  ] Install X-Code and brew. Can't be executed as root."

    ```
    * To build a wazuh-agent package for tag v3.7.2 with 4 jobs:
        `# sudo ./generate_wazuh_packages.sh -b v3.7.2 -j 4`.

    * To install `Packages` tool:
        `# sudo ./generate_wazuh_packages.sh -i `.

    * To install `brew` and `X-Code` tool:
        `$ ./generate_wazuh_packages.sh -x`.

3. When the execution finishes, you can find your `.pkg` packages in specified folder (with parameter `-s`), by default in the script path.


# Aditional information

Use the `generate_wazuh_packages.sh` script for build packages for macOS.

The `package_files` contains some files used by the `Buildpackages` tool to generate the package. The most important file is `wazuh-agent-pkgproj`, which is used by `Buildpackages` to generate the package and have to be updated by the script with the specs and default Wazuh configurations. Also, there are two scripts, `postinstall.sh` and `preinstall.sh` that are loaded in the package to be executed during the installation, and the `build.sh` scripts defines how to compile the Wazuh Agent.

The specs folder contains the `pkgproj` files which are used to generate the `wazuh-agent.pkgproj` file.

## More Packages

- [RPM](/rpms/README.md)
- [Debian](/debs/README.md)
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
