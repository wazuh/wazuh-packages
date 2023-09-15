# Update the Operating System (OS) packages to ensure the OS is up to date
sudo yum update -y

# Install and enable the FIPS module
sudo yum install -y dracut-fips
sudo dracut -f

# Enable FIPS mode by adding kernel argument:
sudo /sbin/grubby --update-kernel=ALL --args="fips=1"
