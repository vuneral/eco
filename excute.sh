#!/bin/bash
#VPS Script By   : Volt
#Contact Me FB   : Nothing Special

# Check Root
if [ "${EUID}" -ne 0 ]; then
echo "You need to run this script as root"
exit 1
fi

# Check System
if [ "$(systemd-detect-virt)" == "openvz" ]; then
echo "OpenVZ is not supported"
exit 1
fi

# Colours
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

# Requirement
apt update -y
apt upgrade -y
update-grub
apt install -y bzip2 gzip coreutils curl
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Script Access 
MYIP=$(wget -qO- icanhazip.com);
echo -e "${green}CHECKING SCRIPT ACCESS${NC}"
IZIN=$( curl https://raw.githubusercontent.com/dopekid30/AutoScriptDebian10/main/Resources/Users/ipvps | grep $MYIP )
if [ $MYIP = $IZIN ]; then
echo -e "${green}ACCESS GRANTED...${NC}"
else
echo -e "${green}ACCESS DENIED...${NC}"
exit 1
fi

# Subdomain Settings
mkdir /var/lib/premium-script;
echo -e "${green}ENTER THE VPS SUBDOMAIN/HOSTNAME, IF NOT AVAILABLE, PLEASE CLICK ENTER${NC}"
read -p "Hostname / Domain: " host
echo "IP=$host" >> /var/lib/premium-script/ipvps.conf
echo "$host" >> /root/domain

# Install SSH/OVPN
wget https://raw.githubusercontent.com/dopekid30/AutoScriptDebian10/main/Resources/Services/Setup && chmod +x Setup && screen -S Setup ./Setup

# Install Script
# download script
cd
wget https://raw.githubusercontent.com/dopekid30/AutoScriptDebian10/main/Resources/Menu/install-premiumscript.sh -O - -o /dev/null|sh

# Restarting Services
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx start
/etc/init.d/openvpn restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/stunnel4 restart
service uwsgi restart
systemctl daemon-reload
/etc/init.d/squid restart
/etc/init.d/webmin restart
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500

# Remove Installation Files
rm -f /root/Setup
rm -f /root/ins-vt.sh

# Finishing
history -c
echo "unset HISTFILE" >> /etc/profile
cd

# Script Information
echo "1.1" > /home/ver
clear
echo " "
echo "INSTALLATION HAS BEEN COMPLETED!!"
echo " "
echo "===========================-AUTOSCRIPT PREMIUM-============================" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "---------------------------------------------------------------------------" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22"  | tee -a log-install.txt
echo "   - OpenVPN                 : TCP 1194"  | tee -a log-install.txt
echo "   - Stunnel4                : 442"  | tee -a log-install.txt
echo "   - Dropbear                : 109, 143"  | tee -a log-install.txt
echo "   - Squid Proxy             : 3128, 8080 (limit to IP Server)"  | tee -a log-install.txt
echo "   - Badvpn                  : 7100, 7200, 7300"  | tee -a log-install.txt
echo "   - Nginx                   : 80, 89"  | tee -a log-install.txt
echo "   - V2RAY Vmess TLS         : 443"  | tee -a log-install.txt
echo "   - V2RAY Vmess None TLS    : 82"  | tee -a log-install.txt
echo "   - V2RAY Vless TLS         : 5443"  | tee -a log-install.txt
echo "   - V2RAY Vless None TLS    : 880"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone                : Africa/Johannesburg (GMT +2)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot             : [OFF]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Webmin Login Page       : http://$MYIP:10000" | tee -a log-install.txt
echo "   - Download OpenVPN Config : http://$MYIP/Dopekid.ovpn" | tee -a log-install.txt
echo "   - Simple OVPN & SSH Panel : http://$MYIP/" | tee -a log-install.txt
echo "   - OpenVPN Monitor Webpage : http://$MYIP:89/" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   - Dev/Main                : Joash Aka Dope~kid"  | tee -a log-install.txt
echo "   - Telegram                : T.me/joash_singh"  | tee -a log-install.txt
echo "   - Whatsapp                : 0846885813"  | tee -a log-install.txt
echo "   - Facebook                : Fb.me/joash.singh.90" | tee -a log-install.txt
echo "---------------------------------------------------------------------------" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "===========================-==================-============================" | tee -a log-install.txt
echo ""
rm -f Debian10
