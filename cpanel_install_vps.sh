#!/bin/bash

# Check if 'screen' is installed
if ! command -v screen &> /dev/null; then
    echo "Screen is not installed. Aborting the script."
    echo "To install run these commands in Almalinux: yum install epel-release -y && yum install screen -y"
    echo "To install run this command in Ubuntu: apt-get update; apt-get install policycoreutils selinux-utils selinux-basics screen -y"
	echo -en '\n'
    exit 1
else
    echo "Screen is installed. Continuing with the script..."
	echo -en '\n'
	sleep 1

    #Set Time Zone
echo -e "\e[1;32mTime Zone Setting\e[0m"
timedatectl set-timezone Asia/Dhaka
sleep 2
echo "--------------------"
echo -en '\n'
echo "Checking the OS"
# Check if it's AlmaLinux
if [ -f /etc/almalinux-release ]; then
    echo -e "\e[1;32mThis is AlmaLinux\e[0m"
    # Run command specific to AlmaLinux
	yum update -y
	echo "--------------------"
	yum install ipset -y
	echo "--------------------"
	yum install libpcap libpcap-devel -y --enablerepo=powertools
	echo "--------------------"
echo -en '\n'
# Check if it's Ubuntu
elif [ -f /etc/os-release ]; then
    if grep -q "Ubuntu" /etc/os-release; then
        echo -e "\e[1;32mThis is Ubuntu\e[0m"
        # Run command specific to Ubuntu
	sudo apt-get install ipset -y
	echo "--------------------"
	sudo apt-get install libpcap0.8 -y
	echo "--------------------"
	sudo apt-get install libpcap0.8-dev -y
	echo "--------------------"
	sudo apt-get install perl
	echo "--------------------"
    else
        echo "This is neither AlmaLinux nor Ubuntu."
    fi
else
    echo "Unable to determine the distribution."
fi
sleep 2
echo -en '\n'
# cPanel Install
echo -e "\e[1;32mInstall cPanel\e[0m"
sleep 1
echo -en '\n'
echo -e "\e[1;32mCheck selinux mode and change it to disabled\e[0m"
if [ -f /etc/selinux/config ]; then
    # Check the current SELinux status
    selinux_mode=$(awk -F= '/^SELINUX=/ {print $2}' /etc/selinux/config)
    
    # Display current SELinux mode
    echo "Current SELinux mode is: $selinux_mode"
    sleep 1
    # Replace "permissive" or "enforcing" with "disabled"
    if [ "$selinux_mode" == "permissive" ] || [ "$selinux_mode" == "enforcing" ]; then
        sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
        echo "SELinux mode updated to 'disabled'"
    else
        echo "SELinux is already set to 'disabled' or the configuration format is not recognized."
    fi
else
    echo "SELinux configuration file (/etc/selinux/config) not found."
fi
echo -en '\n'
sleep 2
echo -e "\e[1;32mSelinux Permanent Disable\e[0m"
setenforce 0
sleep 1
echo -en '\n'
echo -e "\e[1;32mSet Hostname\e[0m"
sleep 1
echo 'Enter new hostname: '
read -r "host_name"
hostnamectl set-hostname "$host_name" --static
sleep 1
echo "Hostname set done"
sleep 2
echo -en '\n'
echo -e "\e[1;32mConfigure cPanel with MariaDB 10.6\e[0m"
sleep 1
mkdir /root/cpanel_profile
cd /root/cpanel_profile
wget https://dhakawebhost.com/serverfiles/cpanel.config
sleep 1
cd
echo -en '\n'
echo -e "\e[1;32mDownloading ea4 file\e[0m"
sleep 1
cd /etc/
wget https://dhakawebhost.com/serverfiles/cpanel_initial_install_ea4_profile.json
sleep 1
echo "Download completed"
sleep 2
echo -en '\n'
echo -e "\e[1;32mDisable NetworkManager\e[0m"
sleep 1
systemctl disable NetworkManager
systemctl stop NetworkManager
sleep 1
echo "NetworkManager Stopped"
sleep 2
echo -en '\n'
echo -e "\e[1;32mStart cPanel Installation\e[0m"
sleep 1
cd /home && curl -o latest -L https://securedownloads.cpanel.net/latest && sh latest
sleep 2
echo -en '\n'
echo -e "\e[1;32mInstalling CSF Firewall\e[0m"
sleep 1
cd /usr/src
rm -fv csf.tgz
wget https://download.configserver.com/csf.tgz
tar -xzf csf.tgz
cd csf
sh install.sh
sleep 2
echo "CSF Firewall installed"
echo -en '\n'
echo -e "\e[1;32mReplacing csf.conf file\e[0m"
sleep 1
cd /etc/csf
mv csf.conf csf.conf.bak
wget https://dhakawebhost.com/serverfiles/csf.conf
sleep 1
echo "Done"
sleep 2
echo -en '\n'

echo -e "\e[1;32mInstalling ModSecurity\e[0m"
sleep 1
cd /usr/src
rm -fv /usr/src/cmc.tgz
wget http://download.configserver.com/cmc.tgz
tar -xzf cmc.tgz
cd cmc
sh install.sh
rm -Rfv /usr/src/cmc*
sleep 1
cd
echo -en '\n'
sleep 2
echo -en '\n'
echo -e "\e[1;32mDisable Compiler\e[0m"
sleep 1
/scripts/compilers off
echo "Done"
echo -en '\n'
echo -e "\e[1;32mDisable cPHulk\e[0m"
sleep 1
whmapi1 configureservice service=cphulkd enabled=0 monitored=0
/usr/local/cpanel/etc/init/stopcphulkd
/usr/local/cpanel/bin/cphulk_pam_ctl --disable
echo "Done"
echo -en '\n'
echo -e "\e[1;32mInstalling LiteSpeed Plugin\e[0m"
sleep 1
cd /usr/src; curl https://www.litespeedtech.com/packages/cpanel/lsws_whm_plugin_install.sh | sh
sleep 1
cd
echo -en '\n'
sleep 2
echo -e "\e[1;32mInstallation Completed\e[0m"
echo -en '\n'
fi

