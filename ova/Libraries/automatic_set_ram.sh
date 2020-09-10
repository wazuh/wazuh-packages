etc_elastic="/etc/elasticsearch"
ram_gb=$(free -m | awk '/^Mem:/{print $2}')
ram=$(( ${ram_gb} / 2 ))

sed -i "s/-Xms[0-9]\+[gm]/-Xms${ram}m/" "${etc_elastic}/jvm.options"
sed -i "s/-Xmx[0-9]\+[gm]/-Xmx${ram}m/" "${etc_elastic}/jvm.options"
