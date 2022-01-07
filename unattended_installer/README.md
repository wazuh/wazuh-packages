Wazuh unattended installer
==========================

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/wazuh)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)

## Goal

The Wazuh unattended installer is a tool that helps you to install and configure all Wazuh components, whatever be your architecture (All-in-One, distributed on no matter how many Wazuh or Elasticsearch nodes).

## Examples

We will show the use of this tool using 3 scenarios:

- [All components work in the same host, the All-in-one scenario.](#All-in-one)
- [Mixed distributed](#Mixed): every component will be installed separately, but conforming to a Wazuh cluster and Elasticsearch cluster:
    - Host #1: Wazuh manager - master node & Elasticsearch node.
    - Host #2: Wazuh manager - worker node & Elasticsearch node.
    - Host #3: Wazuh manager - worker node & Elasticsearch node.
- [All distributed](#Distributed): every component will be installed on a different host. In this example, we will work on 6 hosts, a two nodes Wazuh cluster, a three Elasticsearch cluster and a Kibana node:
    - Host #1: Wazuh manager - master node.
    - Host #2: Wazuh manager - worker node.
    - Host #3: Elasticsearch node.
    - Host #4: Elasticsearch node.
    - Host #5: Elasticsearch node.
    - Host #6: Kibana node.



### All-in-one

Clone the repository:
```
git clone --branch unify-unattended https://github.com/wazuh/wazuh-packages
cd wazuh-packages/unattended_installer/
```

For a fresh installation:
```
./wazuh_install.sh -l -a
```

Example <details><summary>Output</summary>

```
07/01/2022 19:14:42 INFO: Creating the Root certificate.
07/01/2022 19:14:42 INFO: Creating the Elasticsearch certificates.
07/01/2022 19:14:42 INFO: Creating the Wazuh server certificates.
07/01/2022 19:14:43 INFO: Creating the Kibana certificate.
07/01/2022 19:14:43 INFO: Generating random passwords.
07/01/2022 19:14:43 INFO: Starting all necessary utility installation.
07/01/2022 19:14:49 INFO: All necessary utility installation finished.
07/01/2022 19:14:49 INFO: Adding the Wazuh repository.
07/01/2022 19:14:51 INFO: Wazuh repository added.
07/01/2022 19:14:51 INFO: Starting Open Distro for Elasticsearch installation.
07/01/2022 19:15:34 INFO: Open Distro for Elasticsearch installation finished.
07/01/2022 19:15:36 INFO: Elasticsearch post-install configuration finished.
07/01/2022 19:15:36 INFO: Starting service elasticsearch.
07/01/2022 19:15:50 INFO: Elasticsearch service started.
07/01/2022 19:15:50 INFO: Starting Elasticsearch cluster.
07/01/2022 19:16:01 INFO: Elasticsearch cluster initialized.
07/01/2022 19:16:02 INFO: wazuh-alerts template inserted into the Elasticsearch cluster.
07/01/2022 19:16:02 INFO: Setting passwords.
07/01/2022 19:16:03 INFO: Creating password backup.
07/01/2022 19:16:08 INFO: Password backup created
07/01/2022 19:16:08 INFO: Generating password hashes.
07/01/2022 19:16:14 INFO: Password hashes generated.
07/01/2022 19:16:14 INFO: Loading new passwords changes.
07/01/2022 19:16:18 INFO: Passwords changed.
07/01/2022 19:16:18 INFO: Elasticsearch cluster started.
07/01/2022 19:16:18 INFO: Starting the Wazuh manager installation.
07/01/2022 19:17:07 INFO: Wazuh manager installation finished.
07/01/2022 19:17:07 INFO: Starting service wazuh-manager.
07/01/2022 19:17:26 INFO: Wazuh-manager service started.
07/01/2022 19:17:26 INFO: Starting filebeat installation.
07/01/2022 19:17:32 INFO: Filebeat installation finished.
07/01/2022 19:17:32 INFO: Filebeat post-install configuration finished.
07/01/2022 19:17:32 INFO: Starting service filebeat.
07/01/2022 19:17:33 INFO: Filebeat service started.
07/01/2022 19:17:33 INFO: Starting Kibana installation.
07/01/2022 19:18:10 INFO: Kibana installation finished.
07/01/2022 19:18:10 INFO: Starting Wazuh Kibana plugin installation.
07/01/2022 19:18:22 INFO: Wazuh Kibana plugin installation finished.
07/01/2022 19:18:22 INFO: Kibana certificate setup finished.
07/01/2022 19:18:23 INFO: Kibana post-install configuration finished.
07/01/2022 19:18:23 INFO: Starting service kibana.
07/01/2022 19:18:24 INFO: Kibana service started.
07/01/2022 19:18:24 INFO: Setting passwords.
07/01/2022 19:18:25 INFO: Creating password backup.
07/01/2022 19:18:31 INFO: Password backup created
07/01/2022 19:18:31 INFO: Generating password hashes.
07/01/2022 19:18:37 INFO: Password hashes generated.
07/01/2022 19:18:37 INFO: Filebeat started
07/01/2022 19:18:37 INFO: Kibana started
07/01/2022 19:18:37 INFO: Loading new passwords changes.
07/01/2022 19:18:44 INFO: Passwords changed.
07/01/2022 19:18:44 INFO: Starting Kibana (this may take a while).
07/01/2022 19:18:54 INFO: Kibana started.
07/01/2022 19:18:54 INFO: You can access the web interface https://<kibana-host-ip>. The credentials are admin:b9xK5HRUgE2YAOe7JsTPK9gmSMBoLzXV
07/01/2022 19:18:54 INFO: Installation finished.
```

</details>

### Mixed

Clone the repository:
```
git clone --branch unify-unattended https://github.com/wazuh/wazuh-packages
cd wazuh-packages/unattended_installer/
```

Describe the architecture using the file `config.yml`. You can find an example in `config/opendistro/certificate/config.yml` and save it at the same level as `wazuh_installer.sh`:
```
nodes:
  # Elasticsearch server nodes
  elasticsearch:
    name: elastic1
    ip: 172.16.1.89
    name: elastic2
    ip: 172.16.1.99
    name: elastic3
    ip: 172.16.1.109

  # Wazuh server nodes
  # Use node_type only with more than one Wazuh manager
  wazuh_servers:
    name: manager1
    ip: 172.16.1.89
    node_type: master
    name: manager2
    ip: 172.16.1.99
    node_type: worker
    name: manager3
    ip: 172.16.1.109
    node_type: worker

  # Kibana node
  kibana:
    name: kibana1
    ip: 172.16.1.89
    name: kibana2
    ip: 172.16.1.99
    name: kibana3
    ip: 172.16.1.109
```

After describing the architecture, certificates must be created:
```
./wazuh_install.sh -l -c
```
<details><summary>Output</summary>

```
07/01/2022 18:21:29 INFO: Creating the Root certificate.
07/01/2022 18:21:29 INFO: Creating the Elasticsearch certificates.
07/01/2022 18:21:30 INFO: Creating the Wazuh server certificates.
07/01/2022 18:21:30 INFO: Creating the Kibana certificate.
07/01/2022 18:21:30 INFO: Generating random passwords.
```

</details>
<br>

Copy the `certs.tar` and `config.yml` in all the nodes, at the same level as `wazuh_install.sh`. 

After `certs.tar` and `config.yml` distribution over all nodes, you can start installing components:

**Host #1**

Install Elasticsearch:
```
./wazuh_install.sh -l -e elastic1 -i
```
<details><summary>Output</summary>

```
07/01/2022 18:23:46 WARNING: Health-check ignored.
07/01/2022 18:23:46 INFO: Starting all necessary utility installation.
07/01/2022 18:23:53 INFO: All necessary utility installation finished.
07/01/2022 18:23:53 INFO: Adding the Wazuh repository.
07/01/2022 18:23:55 INFO: Wazuh repository added.
07/01/2022 18:23:55 INFO: Starting Open Distro for Elasticsearch installation.
07/01/2022 18:24:18 INFO: Open Distro for Elasticsearch installation finished.
07/01/2022 18:24:18 INFO: Configuring Elasticsearch.
07/01/2022 18:24:21 INFO: Starting service elasticsearch.
07/01/2022 18:24:57 INFO: Elasticsearch service started.
07/01/2022 18:24:57 INFO: Starting Elasticsearch cluster.
07/01/2022 18:24:57 INFO: Elasticsearch cluster started.
07/01/2022 18:24:57 INFO: Installation finished.
```

</details>
<br>

Install Wazuh manager:
```
./wazuh_install.sh -l -w manager1 -i
```
<details><summary>Output</summary>

```
07/01/2022 18:34:03 WARNING: Health-check ignored.
07/01/2022 18:34:03 INFO: Starting all necessary utility installation.
07/01/2022 18:34:07 INFO: All necessary utility installation finished.
07/01/2022 18:34:07 INFO: Adding the Wazuh repository.
07/01/2022 18:34:07 INFO: Wazuh repository already exists. Skipping addition.
07/01/2022 18:34:07 INFO: Wazuh repository added.
07/01/2022 18:34:07 INFO: Starting the Wazuh manager installation.
07/01/2022 18:35:16 INFO: Wazuh manager installation finished.
07/01/2022 18:35:16 INFO: Starting service wazuh-manager.
07/01/2022 18:35:41 INFO: Wazuh-manager service started.
07/01/2022 18:35:41 INFO: Starting filebeat installation.
07/01/2022 18:35:54 INFO: Filebeat installation finished.
07/01/2022 18:35:55 INFO: Filebeat post-install configuration finished.
07/01/2022 18:35:55 INFO: Setting passwords.
07/01/2022 18:35:57 INFO: Filebeat started
07/01/2022 18:35:57 INFO: Starting service filebeat.
07/01/2022 18:36:00 INFO: Filebeat service started.
07/01/2022 18:36:00 INFO: Installation finished.
```

</details>
<br>

Repeat the described Elasticsearch and Wazuh managers steps on **hosts #2 and #3** changing the node name `elastic1` by `elastic2` or `elastic3` and `manager1` by `manager2` or `manager3`.

After having three hosts with Elasticsearch and Wazuh manager installed, choose an Elasticsearch node and run the following command to initialize the security configuration:
```
./wazuh_install.sh -l -s
```


<details><summary>Output</summary>

```
07/01/2022 18:30:21 INFO: Elasticsearch cluster initialized.
07/01/2022 18:30:23 INFO: wazuh-alerts template inserted into the Elasticsearch cluster.
07/01/2022 18:30:23 INFO: Setting passwords.
07/01/2022 18:30:25 INFO: Creating password backup.
07/01/2022 18:30:31 INFO: Password backup created
07/01/2022 18:30:31 INFO: Generating password hashes.
07/01/2022 18:30:38 INFO: Password hashes generated.
07/01/2022 18:30:38 INFO: Loading new passwords changes.
07/01/2022 18:30:45 INFO: Passwords changed.
07/01/2022 18:30:45 INFO: Elasticsearch cluster started.
```

</details>
<br>

Lastly, install Kibana. Chose the node where you want to install Kibana and run the following command using the corresponding node name. In this example, Kibana will be installed in #2 host:
```
./wazuh_install.sh -l -k kibana2 -i
```
<details><summary>Output</summary>

```
07/01/2022 19:02:00 WARNING: Health-check ignored.
07/01/2022 19:02:00 INFO: Starting all necessary utility installation.
07/01/2022 19:02:04 INFO: All necessary utility installation finished.
07/01/2022 19:02:04 INFO: Adding the Wazuh repository.
07/01/2022 19:02:04 INFO: Wazuh repository already exists. Skipping addition.
07/01/2022 19:02:04 INFO: Wazuh repository added.
07/01/2022 19:02:04 INFO: Starting Kibana installation.
07/01/2022 19:02:31 INFO: Kibana installation finished.
07/01/2022 19:02:42 INFO: Wazuh Kibana plugin installed.
07/01/2022 19:02:43 INFO: Kibana certificate setup finished.
07/01/2022 19:02:43 INFO: Setting passwords.
07/01/2022 19:02:45 INFO: Filebeat started
07/01/2022 19:02:45 INFO: Kibana started
07/01/2022 19:02:45 INFO: Starting service kibana.
07/01/2022 19:02:46 INFO: Kibana service started.
07/01/2022 19:02:46 INFO: Starting Kibana (this may take a while).
07/01/2022 19:02:57 INFO: Kibana started.
07/01/2022 19:02:57 INFO: You can access the web interface https://172.16.1.99. The credentials are admin:StwK7YTE4JWIFwbEkpFg9emDoTzi9RJr
07/01/2022 19:02:57 INFO: Installation finished.
```

</details>

### Distributed

Clone the repository on every host:
```
git clone --branch unify-unattended https://github.com/wazuh/wazuh-packages
cd wazuh-packages/unattended_installer/
```

**Host #1**

Describe the architecture using the file `config.yml`. You can find an example in `config/opendistro/certificate/config.yml` and save it at the same level as `wazuh_installer.sh`:
```
nodes:
  # Elasticsearch server nodes
  elasticsearch:
    name: elastic1
    ip: 172.16.1.39
    name: elastic2
    ip: 172.16.1.49
    name: elastic3
    ip: 172.16.1.59

  # Wazuh server nodes
  # Use node_type only with more than one Wazuh manager
  wazuh_servers:
    name: manager1
    ip: 172.16.1.19
    node_type: master
    name: manager2
    ip: 172.16.1.29
    node_type: worker

  # Kibana node
  kibana:
    name: kibana1
    ip: 172.16.1.69
```


After describing the architecture, certificates must be created:
```
./wazuh_install.sh -l -c
```
<details><summary>Output</summary>

```
07/01/2022 19:49:41 INFO: Creating the Root certificate.
07/01/2022 19:49:41 INFO: Creating the Elasticsearch certificates.
07/01/2022 19:49:42 INFO: Creating the Wazuh server certificates.
07/01/2022 19:49:42 INFO: Creating the Kibana certificate.
07/01/2022 19:49:42 INFO: Generating random passwords.
```

</details>
<br>

Copy the `certs.tar` and `config.yml` in all the nodes, at the same level as `wazuh_install.sh`. After `certs.tar` and `config.yml` distribution over all nodes, you can start installing components.

Install Wazuh manager:
```
./wazuh_install.sh -l -i -w manager1
```
<details><summary>Output</summary>

```
07/01/2022 19:50:14 WARNING: Health-check ignored.
07/01/2022 19:50:14 INFO: Starting all necessary utility installation.
07/01/2022 19:50:23 INFO: All necessary utility installation finished.
07/01/2022 19:50:23 INFO: Adding the Wazuh repository.
07/01/2022 19:50:26 INFO: Wazuh repository added.
07/01/2022 19:50:26 INFO: Starting the Wazuh manager installation.
07/01/2022 19:51:12 INFO: Wazuh manager installation finished.
07/01/2022 19:51:12 INFO: Starting service wazuh-manager.
07/01/2022 19:51:38 INFO: Wazuh-manager service started.
07/01/2022 19:51:38 INFO: Starting filebeat installation.
07/01/2022 19:51:48 INFO: Filebeat installation finished.
07/01/2022 19:51:49 INFO: Filebeat post-install configuration finished.
07/01/2022 19:51:49 INFO: Setting passwords.
07/01/2022 19:51:50 INFO: Filebeat started
07/01/2022 19:51:50 INFO: Starting service filebeat.
07/01/2022 19:51:52 INFO: Filebeat service started.
07/01/2022 19:51:52 INFO: Installation finished.
```

</details>
<br>

**Host #2**

Install Wazuh manager:
```
./wazuh_install.sh -l -i -w manager2
```

**Host #3**

Install Elasticsearch node:
```
./wazuh_install.sh -l -i -e elastic1
```
<details><summary>Output</summary>

```
07/01/2022 19:52:49 WARNING: Health-check ignored.
07/01/2022 19:52:49 INFO: Starting all necessary utility installation.
07/01/2022 19:52:57 INFO: All necessary utility installation finished.
07/01/2022 19:52:58 INFO: Adding the Wazuh repository.
07/01/2022 19:53:00 INFO: Wazuh repository added.
07/01/2022 19:53:00 INFO: Starting Open Distro for Elasticsearch installation.
07/01/2022 19:53:37 INFO: Open Distro for Elasticsearch installation finished.
07/01/2022 19:53:37 INFO: Configuring Elasticsearch.
07/01/2022 19:53:41 INFO: Starting service elasticsearch.
07/01/2022 19:54:35 INFO: Elasticsearch service started.
07/01/2022 19:54:35 INFO: Starting Elasticsearch cluster.
07/01/2022 19:54:36 INFO: Elasticsearch cluster started.
07/01/2022 19:54:36 INFO: Installation finished.
```

</details>
<br>

**Host #4**

Install Elasticsearch node:
```
./wazuh_install.sh -l -i -e elastic2
```

**Host #5**

Install Elasticsearch node:
```
./wazuh_install.sh -l -i -e elastic3
```

**At any elasticsearch host**
On any elasticsearch host (#3, #4 or #5 in our example), run:
```
./wazuh_install.sh -l -s
```
<details><summary>Output</summary>

```
07/01/2022 19:56:17 INFO: Elasticsearch cluster initialized.
07/01/2022 19:56:18 INFO: wazuh-alerts template inserted into the Elasticsearch cluster.
07/01/2022 19:56:18 INFO: Setting passwords.
07/01/2022 19:56:20 INFO: Creating password backup.
07/01/2022 19:56:28 INFO: Password backup created
07/01/2022 19:56:28 INFO: Generating password hashes.
07/01/2022 19:56:38 INFO: Password hashes generated.
07/01/2022 19:56:38 INFO: Loading new passwords changes.
07/01/2022 19:56:47 INFO: Passwords changed.
07/01/2022 19:56:47 INFO: Elasticsearch cluster started.
```

</details>
<br>

**Host #6**

Install Kibana:

```
./wazuh_install.sh -l -i -k kibana1
```
<details><summary>Output</summary>

```
07/01/2022 19:56:51 WARNING: Health-check ignored.
07/01/2022 19:56:51 INFO: Starting all necessary utility installation.
07/01/2022 19:56:59 INFO: All necessary utility installation finished.
07/01/2022 19:56:59 INFO: Adding the Wazuh repository.
07/01/2022 19:57:01 INFO: Wazuh repository added.
07/01/2022 19:57:01 INFO: Starting Kibana installation.
07/01/2022 19:57:43 INFO: Kibana installation finished.
07/01/2022 19:57:54 INFO: Wazuh Kibana plugin installed.
07/01/2022 19:57:55 INFO: Kibana certificate setup finished.
07/01/2022 19:57:55 INFO: Setting passwords.
07/01/2022 19:57:56 INFO: Kibana started
07/01/2022 19:57:56 INFO: Starting service kibana.
07/01/2022 19:57:58 INFO: Kibana service started.
07/01/2022 19:57:58 INFO: Starting Kibana (this may take a while).
07/01/2022 19:58:09 INFO: Kibana started.
07/01/2022 19:58:09 INFO: You can access the web interface https://172.16.1.69. The credentials are admin:hQB3bdFzQt5TCcaME14nwGnps4rQNLXU
07/01/2022 19:58:09 INFO: Installation finished.
```

</details>

## License and copyright

WAZUH
Copyright (C) 2015-2022 Wazuh Inc.  (License GPLv2)
