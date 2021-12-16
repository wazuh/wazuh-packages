parse_yaml () {
   local prefix=$2
   local s='[[:space:]]*' w='[a-zA-Z0-9_]*' fs=$(echo @|tr @ '\034')
   sed -ne "s|^\($s\):|\1|" \
        -e "s|^\($s\)\($w\)$s:$s[\"']\(.*\)[\"']$s\$|\1$fs\2$fs\3|p" \
        -e "s|^\($s\)\($w\)$s:$s\(.*\)$s\$|\1$fs\2$fs\3|p"  $1 |
   awk -F$fs '{
      indent = length($1)/2;
      vname[indent] = $2;
      for (i in vname) {if (i > indent) {delete vname[i]}}
      if (length($3) > 0) {
         vn=""; for (i=0; i<indent; i++) {vn=(vn)(vname[i])("_")}
         printf("%s%s%s=\"%s\"\n", "'$prefix'",vn, $2, $3);
      }
   }'
}

parse_yaml ./config.yml

vars="elasticsearch_node_names=( $(parse_yaml ./config.yml | grep certificates_elasticsearch_name | sed 's/certificates_elasticsearch_name=//') )"
eval $vars
vars="wazuh_servers_node_names=( $(parse_yaml ./config.yml | grep certificates_wazuh_servers_name | sed 's/certificates_wazuh_servers_name=//') )"
eval $vars
vars="kibana_node_names=( $(parse_yaml ./config.yml | grep certificates_kibana_name | sed 's/certificates_kibana_name=//') )"
eval $vars

vars="elasticsearch_node_ips=( $(parse_yaml ./config.yml | grep certificates_elasticsearch_ip | sed 's/certificates_elasticsearch_ip=//') )"
eval $vars
vars="wazuh_servers_node_ips=( $(parse_yaml ./config.yml | grep certificates_wazuh_servers_ip | sed 's/certificates_wazuh_servers_ip=//') )"
eval $vars
vars="kibana_node_ips=( $(parse_yaml ./config.yml | grep certificates_kibana_ip | sed 's/certificates_kibana_ip=//') )"
eval $vars

vars=$(parse_yaml ./config.yml)
eval $vars

