# This file is needed by wazuh-jenkins repository

workspace="."
path_ova="./output/wazuh-4.1.4_1.12.0.ova"
dest_ova="./output/wazuh-4.1.4_1.12.0_new.ova"
ovf_path="./new-ova/wazuh-4.1.4_1.12.0.ovf"
wazuh_version="4.1.4"
opendistro_version="1.12.0"
file="wazuh-${wazuh_version}_${opendistro_version}"
mkdir -p ${workspace}/new-ova/


echo "Setting OVA to default"

tar -xvf ${path_ova} --directory ${workspace}/new-ova/
mv "${workspace}"/new-ova/*.ovf ${workspace}/new-ova/${file}.ovf
mv "${workspace}"/new-ova/*.mf ${workspace}/new-ova/${file}.mf
mv "${workspace}"/new-ova/*.vmdk ${workspace}/new-ova/${file}-disk-1.vmdk
cp ${ovf_path} ${workspace}/new-ova/${file}.ovf

sed -i "s/{WAZUH_VERSION}/${wazuh_version}/" ${workspace}/new-ova/${file}.ovf
sed -i "s/{OPENDISTRO_VERSION}/${opendistro_version}/" ${workspace}/new-ova/${file}.ovf
echo "OVF changed"

ovf_size=$(stat --printf=%s ${workspace}/new-ova/${file}-disk-1.vmdk)
sed -i "s/{SIZE}/${ovf_size}/" "${workspace}/new-ova/${file}.ovf"   

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