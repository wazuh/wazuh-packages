
users=( admin kibanaserver kibanaro logstash readall snapshotrestore wazuh_admin wazuh_user )
api_users=( wazuh wazuh-wui )

echo '::group:: Change all, no API ...'

mapfile -t pass < <(bash wazuh-passwords-tool.sh -a | awk '{ print $NF }' | sed \$d | sed '1d' )
for i in "${!users[@]}"; do
 if curl -XGET https://localhost:9200/ -u "${users[i]}":"${pass[i]}" -k -w %{http_code} | grep "401"; then
  exit 1
 fi
done

echo '::endgroup::'

echo '::group:: Change all from file, no API ...'

mapfile -t passf < <(bash wazuh-passwords-tool.sh -f wazuh-install-files/wazuh-passwords.txt | awk '{ print $NF }' | sed \$d | sed '1d' )
for i in "${!users[@]}"; do
 if curl -XGET https://localhost:9200/ -u "${users[i]}":"${passf[i]}" -k -w %{http_code} | grep "401"; then
  exit 1
 fi
done

echo '::endgroup::'

echo '::group:: Change all passwords from file using API credentials ...'

mapfile -t passall < <(bash wazuh-passwords-tool.sh -f wazuh-install-files/wazuh-passwords.txt -au wazuh -ap BkJt92r*ndzN.CkCYWn?d7i5Z7EaUt63 | awk '{ print $NF }' | sed \$d ) 
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

echo '::group::'
