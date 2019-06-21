Wazuh MSI packages
==================

In this repository, you can find the necessary tools to build a Wazuh msi package for windows.

## Tools needed to build the package

To build a Wazuh package you need to install the following tools:
  - `docker`: [installation guide](https://docs.docker.com/install/linux/docker-ce/centos/).
  - `git`: `yum install git`.
  - `.NET framework 3.5.1`: [Installation](https://www.microsoft.com/en-us/download/details.aspx?id=22)
  - `Microsoft Windows SDK`: [Installation](https://developer.microsoft.com/en-US/windows/downloads/windows-10-sdk)

## Building MSI packages

To build an MSI package, you need to download this repository and execute the `generate_wazuh_msi.ps1` script on a powershell terminal. This script will  create a docker image and run a Docker container  that will compile a wiazuh windows agent, then it pass the sources to the host windows machine that will generate the msi package.

1. Download this repository and go to the rpm directory:
    ```bash
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-packages/windows
    ```

2. Execute the `generate_wazuh_msi.ps1` script to build the package. There are multiple parameters to select:
```shellsession
    # ./generate_wazuh_msi.sh -help

    Usage: generate_wazuh_msi.ps1 -BRANCH_TAG <BRANCH> -REVISION <REV> -JOBS <N_JOBS>
        Arguments description:
        -BRANCH_TAG <BRANCH>            [Required] Select Git branch or tag e.g. v3.9.2
        -REVISION <REV>                 [Required] Package revision that append to version e.g. x.x.x-rev
        -DESTINATION <DESTINATION_DIR>  [Required] Destination directory
        -JOBS <N_JOBS>                  [Optional] Number of parallel jobs when compiling.
        -CHECKSUM <CHECKSUM_DIR>        [Optional] Generate checksum file for the generated package.
        -SIGN                           [Optional] Sign packages
        -help                           Show this help.
```

By default PowerShell doesnt allow the execution of scripts, to execute this script you will have to either change the execution policy of your system or change it temporarily wile the script is runinig by runinig the script like this:
```shellsession
PowerShell.exe -ExecutionPolicy Bypass -File .\generate_wazuh_msi.ps1
```

* To build a wazuh msi package for tag v3.9.2, revision my_rev and store it in  `C:\\Users\myuser\desktop`:

        `PowerShell.exe -ExecutionPolicy Bypass -File .\generate_wazuh_msi.ps1 -BRANCH_TAG v3.9.2 -REVISION my_rev -DESTINATION /C:\\Users\myuser\desktop`.

* To build a wazuh msi package for tag v3.9.2, revision my_rev and store it in  `C:\\Users\myuser\desktop`, sign the package and generate the sha512 checksum of the package in `C:\\Users\myuser\desktop\checksum` :

        `PowerShell.exe -ExecutionPolicy Bypass -File .\generate_wazuh_msi.ps1 -BRANCH_TAG v3.9.2 -REVISION my_rev -DESTINATION /C:\\Users\myuser\desktop -CHECKSUM C:\\Users\myuser\desktop\checksum -SIGN`.

3. When the execution finishes, you can find your `.msi` package in the specified folder.

## More Packages

- [RPM](/rpms/README.md)
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
