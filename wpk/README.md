WPK package
=====

In this repository, you can find the necessary tools to build a WPK package.

## Tools needed to build the package
- `docker`: [installation guide](https://docs.docker.com/install)

## Building WPK packages

To build  a WPK package, it is necessary to generate a X509 certificate and CA, and run the `generate_wpk_package.sh` script. This script will download the source code from the [wazuh/wazuh](https://github.com/wazuh/wazuh) repository, build a Docker image with all the necessary tools to build the app package and run a Docker container from that image that will generate a `.wpk` package.

1. Download this repository and go to the wazuhapp directory:
    ```shellsession
    $ git clone https://github.com/wazuh/wazuh-packages && cd wazuh-installers/wpk
    ```
2. Generate X509 certificate and CA, if you already have them you can skip this step

    ```shellsession
    # openssl req -x509 -new -nodes -newkey rsa:2048 -keyout wpk_root.key -out wpk_root.pem -batch
    ```
    ```shellsession
    # openssl req -new -nodes -newkey rsa:2048 -keyout wpkcert.key -out wpkcert.csr -subj '/C=US/ST=CA/O=Wazuh'
    ```
    Set the location as follows:

    - /C=US is the country.
    - /ST=CA is the state.
    - /O=Wazuh is the organization’s name.

    ```shellsession
    # openssl x509 -req -days 365 -in wpkcert.csr -CA wpk_root.pem -CAkey wpk_root.key -out wpkcert.pem -CAcreateserial
    ```
3. Execute the `generate_wpk_package.sh` script to build the package. There are multiple parameters to select, Here you can see all the different parameters:
    ```shellsession
    $ ./generate_wpk_package.sh -h

    Usage: /wazuh-installers/wpk-docker/generate_wpk_package.sh [OPTIONS]

        -t,   --target-system <target>              [Required] Select target wpk to build [linux/windows]
        -b,   --branch <branch>                     [Required] Select Git branch or tag e.g.
        -d,   --destination <path>                  [Required] Set the destination path of package.
        -k,   --key-dir <arch>                      [Required] Set the WPK key path to sign package.
        -a,   --architecture <arch>                 [Optional] Target architecture of the package [x86_64].
        -j,   --jobs <number>                       [Optional] Number of parallel jobs when compiling.
        -pd,  --package-directory <directory>       [Required for windows] Path to the package name to pack on wpk.
        -o,   --output <name>                       [Required] Name to the output package.
        -h,   --help                                Show this help.
    ```
    * To build the WPK package for linux called linux-3_9_0.wpk from tag v3.9.0 and store it in /home/wpk, while having the keys stored in /tmp/keys

        ```shellsession
        # ./generate_wpk_package.sh -t linux -b v3.9.0 -d /home/wpk -k /tmp/keys -o linux-3_9_0.wpk
        ```
    * To build the WPK package for linux called linux-3_8.wpk from branch 3.8 and store it in /home/wpk, while having the keys stored in /tmp/keys

        ```shellsession
        # ./generate_wpk_package.sh -t linux -b 3.8 -d /home/wpk -k /tmp/keys -o linux-3_8.wpk
        ```
    For windows packages it is necessary to have a msi package, you can find the latest packages here: [wazuh packages](https://documentation.wazuh.com/current/installation-guide/packages-list/index.html#packages)

    * To build the WPK package for windows called windows-3_9_0.wpk from tag v3.9.0 and store it in /home/wpk, while having the keys stored in /tmp/keys and the msi stored in /tmp/msi/wazuh-agent-3.9.0-1.msi
        ```shellsession
        # /generate_wpk_package.sh -t windows -b v3.9.0 -d home/wpk -k /tmp/keys -o windows-3_9_0.wpk -pd /tmp/msi/wazuh-agent-3.9.0-1.msi
        ```
    3. Once the execution finishes, you will find your `.zip` package in the specified folder.

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