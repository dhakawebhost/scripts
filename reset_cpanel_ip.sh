#!/bin/bash

# Function to print messages in different colors
print_color() {
    local color=$1
    local message=$2
    case $color in
        "red")
            echo -e "\e[31m$message\e[0m"
            ;;
        "green")
            echo -e "\e[32m$message\e[0m"
            ;;
        "yellow")
            echo -e "\e[33m$message\e[0m"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Function to restart network services based on the OS
restart_network_services() {
    if [[ -f /etc/almalinux-release ]]; then
        systemctl restart network && systemctl restart ipaliases
    elif [[ -f /etc/lsb-release ]] && grep -q 'Ubuntu' /etc/lsb-release; then
        systemctl restart networking && systemctl restart netplan
    else
        print_color "red" "Unsupported OS"
        exit 1
    fi
}

# Prompt for new IP and hostname
read -p "Enter new IP address: " new_ip
read -p "Enter new hostname: " new_hostname

# 1. Edit /var/cpanel/mainip and replace old IP with new IP
if [ -f /var/cpanel/mainip ]; then
    old_ip=$(cat /var/cpanel/mainip)
    sed -i "s/$old_ip/$new_ip/g" /var/cpanel/mainip
    print_color "green" "Updated /var/cpanel/mainip with new IP: $new_ip"
else
    print_color "red" "File /var/cpanel/mainip does not exist."
    exit 1
fi

# 2. Set the new hostname
hostnamectl set-hostname "$new_hostname"
print_color "green" "Hostname set to: $new_hostname"

# 3. Create /etc/sysconfig/network file and add entry PEERDNS=NO
echo "PEERDNS=NO" > /etc/sysconfig/network
print_color "green" "Added PEERDNS=NO to /etc/sysconfig/network."

# 4. Restart the network server and ipaliases service without disconnecting SSH session
restart_network_services
if [ $? -eq 0 ]; then
    print_color "green" "Network services restarted successfully."
else
    print_color "red" "Failed to restart network services."
    exit 1
fi

# 5. Edit /etc/resolv.conf
if [ -f /etc/resolv.conf ]; then
    cat <<EOL > /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
EOL
    print_color "green" "Updated /etc/resolv.conf with new nameservers."
else
    print_color "red" "File /etc/resolv.conf does not exist."
    exit 1
fi

# 6. Edit /etc/wwwacct.conf and replace ADDR text with ADDR new_ip
if [ -f /etc/wwwacct.conf ]; then
    sed -i "s/^ADDR .*/ADDR $new_ip/" /etc/wwwacct.conf
    print_color "green" "Updated /etc/wwwacct.conf with new IP: ADDR=$new_ip"
else
    print_color "red" "File /etc/wwwacct.conf does not exist."
    exit 1
fi

# 7. Run the cPanel license update command
/usr/local/cpanel/cpkeyclt --force
if [ $? -eq 0 ]; then
    print_color "green" "cPanel license updated successfully."
else
    print_color "red" "Failed to update cPanel license."
fi

# 8. Show the new file configuration
echo
print_color "yellow" "cPanel Main IP:"
cat /var/cpanel/mainip

echo
print_color "yellow" "DNS Information:"
cat /etc/resolv.conf

echo
print_color "yellow" "Peer DNS info:"
cat /etc/sysconfig/network

echo
print_color "yellow" "cPanel New Ac IP:"
grep 'ADDR' /etc/wwwacct.conf

