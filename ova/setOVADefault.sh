
# File adapted to local use 
# Script didnt tested for Jenkins

# ./setOVADefault.sh 4.1.4 1.12.0 output

wazuh_version=$1
opendistro_version=$2

file="wazuh-${wazuh_version}_${opendistro_version}"

path_ova=$3

mkdir new-ova

tar -xvf "${path_ova}/${file}.ova" --directory new-ova/
echo "OVA extracted"

# Change version info
sed -i "s/{WAZUH_VERSION}/${wazuh_version}/" new-ova/${file}.ovf
sed -i "s/{OPENDISTRO_VERSION}/${opendistro_version}/" new-ova/${file}.ovf
echo "OVF changed - Wazuh ${wazuh_version} OpenDistro ${opendistro_version}"

# Calculate vmdk size and insert it in ovf
ovf_size=$(stat --printf=%s new-ova/${file}-disk001.vmdk)
sed -i "s/{SIZE}/${ovf_size}/" "new-ova/${file}.ovf"   
echo "echo OVF changed - VMDK size ${ovf_size} added to OVF"

export workspace
export file

sha_ovf=$(sha1sum new-ova/${file}.ovf)
echo "sha1sum OVF ${sha_ovf}"

sha_vmdk=$(sha1sum new-ova/${file}-disk001.vmdk)
echo "sha1sum VMDK ${sha_vmdk}"

# Delete path of var
read -a sha_ovf_array <<< "${sha_ovf}"
read -a sha_vmdk_array <<< "${sha_vmdk}"
sha_ovf=${sha_ovf_array[0]}
sha_vmdk=${sha_vmdk_array[0]}

# Create file .mf with sha1sum
echo "SHA1(${file}-disk-1.vmdk) = ${sha_vmdk}" > new-ova/${file}.mf
echo "SHA1(${file}.ovf) = ${sha_ovf}" >> new-ova/${file}.mf


# Tar the modified file into .ova file
tar -cvf "output/${file}_new.ova" -C "new-ova/" ${file}.ovf ${file}-disk001.vmdk ${file}.mf

# Check this
rm "output/${file}.ova"
mv "output/${file}_new.ova" "output/${file}.ova"
rm -rf new-ova