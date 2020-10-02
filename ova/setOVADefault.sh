workspace=$1
path_ova=$2
dest_ova=$3
ovf_path=$4
wazuh_version=$5
elk_version=$6
file="wazuh${wazuh_version}_${elk_version}"
mkdir -p ${workspace}/new-ova/


echo "Setting OVA to default"

tar -xvf ${path_ova} --directory ${workspace}/new-ova/
mv "${workspace}"/new-ova/*.ovf ${workspace}/new-ova/${file}.ovf
mv "${workspace}"/new-ova/*.mf ${workspace}/new-ova/${file}.mf
mv "${workspace}"/new-ova/*.vmdk ${workspace}/new-ova/${file}-disk-1.vmdk
cp ${ovf_path} ${workspace}/new-ova/${file}.ovf

sed -i "s/{WAZUH_VERSION}/${wazuh_version}/" ${workspace}/new-ova/${file}.ovf
sed -i "s/{ELASTIC_VERSION}/${elk_version}/" ${workspace}/new-ova/${file}.ovf

echo "OVF changed"

stat --printf=\"%s\" ${workspace}/new-ova/wazuh${wazuh_version}_${elk_version}.ovf
sed -i 's/{SIZE}/${ovf_size}/' ${workspace}/new-ova/${file}.ovf
export workspace
export file
sha_ovf=$(sha1sum ${workspace}/new-ova/${file}.ovf)
sha_vmdk=$(sha1sum ${workspace}/new-ova/${file}-disk-1.vmdk)
read -a sha_ovf_array <<< "${sha_ovf}"
read -a sha_vmdk_array <<< "${sha_vmdk}"

sha_ovf=${sha_ovf_array[0]}
sha_vmdk=${sha_vmdk_array[0]}

echo "SHA1(${file}-disk-1.vmdk) = ${sha_vmdk}" > ${workspace}/new-ova/${file}.mf
echo "SHA1(${file}.ovf) = ${sha_ovf}" >> ${workspace}/new-ova/${file}.mf

tar -cvf "${dest_ova}" -C "${workspace}/new-ova/" ${file}.ovf ${file}-disk-1.vmdk ${file}.mf 
rm -rf ${workspace}/new-ova/
