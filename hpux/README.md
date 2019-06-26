Wazuh HP-UX packages
==================

In this repository, you can find the necessary tools to build a Wazuh package for HP-UX.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
  - `gcc`: [download](http://hpux.connect.org.uk/hppd/cgi-bin/search?term=gcc&Search=Search).
  - `depothelper`: [download](http://hpux.connect.org.uk/hppd/hpux/Sysadmin/depothelper-2.20/).



## Building HP-UX packages

To build a HP-UX package, you need to download this repository and use the `generate_wazuh_packages.sh` script. This script will download the source code from the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository and generate a `tar`package.

1. Download this repository and go to the hpux directory:
    ```bash
    $ curl -L https://github.com/wazuh/wazuh-packages/tarball/master | tar zx
    $ cd wazuh-wazuh-packages-*
    $ cd hpux
    ```

2. Execute the `generate_wazuh_packages.sh` script to build the package. There are multiple parameters to select which package is going to be built, its architecture, etc. Here you can see all the different parameters:
    ```shellsession
    # ./generate_wazuh_packages.sh -h
    This scripts build wazuh package for HPUX.
    USAGE: Command line options available:
        -h, --help       Displays this help.
        -d, --download   Download Wazuh repository.
        -b, --build      Builds HPUX package.
        -u, --utils      Download and install utilities and dependencies.
        -c, --clean-all  Clean sources and generated files.

    USAGE EXAMPLE:
    --------------
        ./generate_wazuh_packages.sh [option] [branch_tag] [revision]
        ./generate_wazuh_packages.sh -d branches/3.3 1
  "
    ```
    * To install the needed dependencies:
        `# ./generate_wazuh_packages.sh -u`.
    * To download the sources from tag v3.9.0:
        `# ./generate_wazuh_packages.sh -d v3.9.0`.
    * To build a wazuh-agent package from the downloaded v3.9.0 sources:
        `# ./generate_wazuh_packages.sh -b v3.9.0`.

3. When the execution finishes, you can find your `tar` in the same directory where the sources are.

## More Packages

- [Debian](/debs/README.md)
- [macOS](/macos/README.md)
- [AIX](/aix/README.md)
- [OVA](/ova/README.md)
- [KibanaApp](/wazuhapp/README.md)
- [SplunkApp](/splunkapp/README.md)
- [WPK](/wpk/README.md)
- [Solaris](/solaris/README.md)
