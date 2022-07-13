#!/bin/bash

users=( admin kibanaserver kibanaro logstash readall snapshotrestore wazuh_admin wazuh_user )
api_users=( wazuh wazuh-wui )

echo '::group:: Change indexer password, password provided'

bash wazuh-passwords-tool.sh -u admin -p LN*X1v.VNtCZ5sESEtLfijPAd39LXGAI
 if ! curl -XGET https://localhost:9200/ -u admin:LN*X1v.VNtCZ5sESEtLfijPAd39LXGAI -k -w %{http_code} | grep "200"; then
  exit 1
 fi
echo '::endgroup::'

echo '::group:: Change indexer password, password no provided'

indx_pass="$(bash wazuh-passwords-tool.sh -u admin | awk '/admin/{ print $NF }' | tr -d \' )"
 if ! curl -XGET https://localhost:9200/ -u admin:"${indx_pass}" -k -w %{http_code} | grep "200"; then
  exit 1
 fi

echo '::endgroup::'

echo '::group:: Change all, no API ...'

mapfile -t pass < <(bash wazuh-passwords-tool.sh -a | awk '{ print $NF }' | sed \$d | sed '1d' )
for i in "${!users[@]}"; do
 if curl -XGET https://localhost:9200/ -u "${users[i]}":"${pass[i]}" -k -w %{http_code} | grep "401"; then
  exit 1
 fi
done

echo '::endgroup::'

echo '::group:: Change all passwords, API credentials ...'

wazuh_pass="$(cat wazuh-install-files/wazuh-passwords.txt | awk "/username: 'wazuh'/{getline;print;}" | awk '{ print $2 }' | tr -d \' )"

mapfile -t passall < <(bash wazuh-passwords-tool.sh -a -au wazuh -ap "${wazuh_pass}" | awk '{ print $NF }' | sed \$d ) 
passindexer=("${passall[@]:0:8}")
passapi=("${passall[@]:(-2)}")

for i in "${!users[@]}"; do
 if curl -XGET https://localhost:9200/ -u "${users[i]}":"${passindexer[i]}" -k -w %{http_code} | grep "401"; then
  exit 1
 fi
done

for i in "${!api_users[@]}"; do
 if ! curl -u "${api_users[i]}":"${passapi[i]}" -w "%{http_code}" -k -X GET "https://localhost:55000/security/user/authenticate" | grep "200"; then
  exit 1
 fi
done
 
echo '::endgroup::'

echo '::group:: Change single API user ...'

bash wazuh-passwords-tool.sh -au wazuh -ap "${passapi[0]}" -u wazuh -p BkJt92r*ndzN.CkCYWn?d7i5Z7EaUt63 -A 
 if ! curl -w "%{http_code}" -u wazuh:BkJt92r*ndzN.CkCYWn?d7i5Z7EaUt63 -k -X GET "https://localhost:55000/security/user/authenticate" | grep "200"; then
  exit 1
 fi
echo '::endgroup::'

echo '::group:: Change all from file, no API ...'

mapfile -t passfile < <(bash wazuh-passwords-tool.sh -f wazuh-install-files/wazuh-passwords.txt | awk '{ print $NF }' | sed \$d | sed '1d' )
for i in "${!users[@]}"; do
 if curl -XGET https://localhost:9200/ -u "${users[i]}":"${passfile[i]}" -k -w %{http_code} | grep "401"; then
  exit 1
 fi
done
echo '::endgroup::'

echo '::group:: Change all passwords from file using API credentials ...'
mapfile -t passallf < <(bash wazuh-passwords-tool.sh -f wazuh-install-files/wazuh-passwords.txt -au wazuh -ap BkJt92r*ndzN.CkCYWn?d7i5Z7EaUt63 | awk '{ print $NF }' | sed \$d ) 
passindexerf=("${passallf[@]:0:8}")
passapif=("${passallf[@]:(-2)}")

for i in "${!users[@]}"; do
 if curl -XGET https://localhost:9200/ -u "${users[i]}":"${passindexerf[i]}" -k -w %{http_code} | grep "401"; then
  exit 1
 fi
done

for i in "${!api_users[@]}"; do
 if ! curl -u "${api_users[i]}":"${passapif[i]}" -w "%{http_code}" -k -X GET "https://localhost:55000/security/user/authenticate" | grep "200"; then
  exit 1
 fi
done

echo '::endgroup::'
