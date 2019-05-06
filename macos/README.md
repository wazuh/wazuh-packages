Wazuh
=====

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

Wazuh is an Open Source Host-based Intrusion Detection System that performs log analysis, file integrity monitoring, policy monitoring, rootkit detection, real-time alerting, active response, vulnerability detector, etc.

In this repository, you can find the necessary tools to build a Wazuh package for OSX.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
  - [Packages](http://s.sudre.free.fr/Software/Packages/about.html): You can install this on OSX using the generate_wazuh_packages.sh script in this repo.
  - `git`: on OSX install with homebrew use `brew install git`

## Building OSX packages

To build an OSX package, you need to download this repository and use the `generate_wazuh_packages.sh` script. This script will download the source code from the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository and automatize the package generation.

1. Download this repository and go to the rpm directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-installers && cd wazuh-installers/osx
    ```

2. Execute the `generate_wazuh_package.sh` script to build the package. There are multiple parameters for selecting which package is going to be built, such as install destination, etc. Also you can install `Packages` using the script. Here you can see all the different parameters:
    ```shellsession
    #macos:osx vagrant$ ./generate_wazuh_packages.sh -h
    
     Usage: ./generate_wazuh_packages.sh [OPTIONS]

    -b, --branch <branch>     [Required] Select Git branch or tag e.g. 
    -d, --destination <path>  [Required] Set the destination absolute path of package.
    -j, --jobs <number>       [Optional] Number of parallel jobs when compiling.
    -r, --revision <rev>      [Optional] Package revision that append to version e.g. x.x.x-rev
    -h, --help                [  Util  ] Show this help.
    -i, --install-deps        [  Util  ] Install build dependencies (Packages).

    ```
    * To build a wazuh-agent package for tag v3.7.2 with 4 jobs:
    
        `# sudo ./generate_wazuh_packages.sh -b v3.7.2 -j 4`.
    * To install Packages:
    
        `# sudo ./generate_wazuh_packages.sh -i `.
        
         
**important detail:** the building of certain branches fails due to incorrect values on the `VERSION` file on the source which generate missing specs. To make a correct building it is recommended to use exacts tags instead of branches. For example, to build a package for Wazuh 3.7 you should use ``` -v v3.7.2 ```

3. When the execution finishes, you can find your `.pkg` packages in specified folder (with parameter -s), by default in the script path.



# Aditional information

Use the `generate_wazuh_packages.sh` script for build packages for OSX.

The `package_files` contains some files used by the Buildpackages tool to generate the package. The most important file is wazuh-agent-pkgproj, which is used by Buildpackages to generate the package and have to be updated by the script with the specs and default Wazuh configurations. Also, there are two scripts, `postinstall.sh` and `preinstall.sh` that are loaded in the package to be executed during the installation.

The specs folder contains the pkgproj files which are used to generate the wazuh-agent.pkgproj file. Sometimes a spec file (pkgproj) for certain version is missing and then, the `generate_wazuh_packages.sh` script generates it based on the most recent version. If that doesn't work maybe it could be because the most recent version has changes that don't work for the compiled one. In this case, a possible solution would be to manually copy the immediately preceding version of the spec and change the version to the right one (Attention: you must change the version in different parts of the file). 

## More Packages

- [RPM](/rpms/README.md)
- [Debian](/debs/README.md)
- [AIX](/aix/README.md)

## Contribute

If you want to contribute to our project please don't hesitate to send a pull request. You can also join our users [mailing list](https://groups.google.com/d/forum/wazuh) by sending an email to [wazuh+subscribe@googlegroups.com](mailto:wazuh+subscribe@googlegroups.com) to ask questions and participate in discussions.

## License and copyright

WAZUH
Copyright (C) 2016-2019 Wazuh Inc.  (License GPLv2)
