etc_elastic="/etc/elasticsearch"
ram_gb=$(free -g | awk '/^Mem:/{print $2}')
ram=$(( ${ram_gb} / 2 ))

if [ ${ram} -eq "0" ]; then
    ram=1;
fi

sed -i "s/-Xms[0-9]\+g/-Xms${ram}g/" ${etc_elastic}/jvm.options
sed -i "s/-Xmx[0-9]\+g/-Xmx${ram}g/" ${etc_elastic}/jvm.options
