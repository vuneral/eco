#!/bin/bash
# Created by volt
# Script by Dani

# Initializing IP
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ifconfig.co);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID

# Stunnel Cert Info
country=MY
state=Malaysia
locality=Kuala_Lumpur
organization=VoltVpn
organizationalunit=VoltVpn
commonname=VoltVpn
email=akuleader11@gmail.com

sudo tee /etc/apt/sources.list.d/pritunl.list << EOF
deb http://repo.pritunl.com/stable/apt buster main
EOF

sudo apt-get install dirmngr
sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com --recv 7568D9BB55FF9E5287D586017AE645C0CF8E292A
sudo apt-get update
sudo apt-get install pritunl-client-electron

# My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
sed -i 's/use_authtok //g' /etc/pam.d/common-password

# Goto Root
cd

# System Setup
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# Reboot Settings
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Set Permissions
chmod +x /etc/rc.local

# Enable On Reboot
systemctl enable rc-local
systemctl start rc-local.service

# Disable IPV6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# Update
apt update -y
apt upgrade -y
apt dist-upgrade -y

# Install Wget And Curl
apt -y install wget curl

# Install Components
apt-get -y install libio-pty-perl libauthen-pam-perl apt-show-versions libnet-ssleay-perl

# Set System Time
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# Removing some duplicated sshd server configs
rm -f /etc/ssh/sshd_config*
 
# Creating a SSH server config using cat eof tricks
cat <<'MySSHConfig' > /etc/ssh/sshd_config
# My OpenSSH Server config
Port 22
Port 220
AddressFamily inet
ListenAddress 0.0.0.0
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin yes
MaxSessions 1024
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
Banner /etc/banner
AcceptEnv LANG LC_*
Subsystem   sftp  /usr/lib/openssh/sftp-server
MySSHConfig

# Restarting openssh service
systemctl restart ssh
 
# NeoFetch
apt-get --reinstall --fix-missing install -y bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip wget net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch git
rm .profile
wget "https://raw.githubusercontent.com/dopekid30/AutoScriptDebian10/main/Resources/Other/.profile" 

# Install Webserver
if [ $(cat /etc/debian_version) == '10.9' ]; then
  VERSION=10.9
  apt -y --purge remove apache2*;
  apt -y install nginx
  apt -y install php-fpm php-cli libssh2-1 php-ssh2 php
  sed -i 's/listen = \/run\/php\/php7.3-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/7.3/fpm/pool.d/www.conf
  rm /etc/nginx/sites-enabled/default
  rm /etc/nginx/sites-available/default
  wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/vuneral/eco/main/module/nginx.conf"
  wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/vuneral/eco/main/module/vps.conf"
  mkdir -p /home/vps/public_html
  wget -O /home/vps/public_html/index.php "https://raw.githubusercontent.com/vuneral/eco/main/module/index.php"
  service php7.3-fpm restart
  service nginx restart
elif [ $(cat /etc/debian_version) == '9.13' ]; then
  VERSION=9.13
  apt -y --purge remove apache2*;
  apt -y install nginx
  apt -y install php7.0-fpm php7.0-cli libssh2-1 php-ssh2 php7.0
  sed -i 's/listen = \/run\/php\/php7.0-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/7.0/fpm/pool.d/www.conf
  rm /etc/nginx/sites-enabled/default
  rm /etc/nginx/sites-available/default
  wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/vuneral/eco/main/module/nginx.conf"
  wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/vuneral/eco/main/module/vps.conf"
  mkdir -p /home/vps/public_html
  wget -O /home/vps/public_html/index.php "https://raw.githubusercontent.com/vuneral/eco/main/module/index.php"
  service php7.0-fpm restart
  service nginx restart
fi

# Install Badvpn
cd
cat <<'badvpnEOF'> /tmp/install-badvpn.bash
#!/bin/bash
if [[ -e /usr/local/bin/badvpn-udpgw ]]; then
 printf "%s\n" "BadVPN-udpgw already installed"
 exit 1
else
 curl -4skL "https://github.com/ambrop72/badvpn/archive/4b7070d8973f99e7cfe65e27a808b3963e25efc3.zip" -o /tmp/badvpn.zip
 unzip -qq /tmp/badvpn.zip -d /tmp && rm -f /tmp/badvpn.zip
 cd /tmp/badvpn-4b7070d8973f99e7cfe65e27a808b3963e25efc3
 cmake -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 &> /dev/null
 make install &> /dev/null
 rm -rf /tmp/badvpn-4b7070d8973f99e7cfe65e27a808b3963e25efc3
 cat <<'EOFudpgw' > /lib/systemd/system/badvpn-udpgw.service
[Unit]
Description=BadVPN UDP Gateway Server daemon
Wants=network.target
After=network.target
[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 4000 --max-connections-for-client 4000 --loglevel info
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOFudpgw
systemctl daemon-reload &>/dev/null
systemctl restart badvpn-udpgw.service &>/dev/null
systemctl enable badvpn-udpgw.service &>/dev/null
fi
badvpnEOF
screen -S badvpninstall -dm bash -c "bash /tmp/install-badvpn.bash && rm -f /tmp/install-badvpn.bash"

# Install Dropbear
apt -y install dropbear
# Removing some duplicate config file
rm -rf /etc/default/dropbear*
 
# creating dropbear config using cat eof tricks
cat <<'MyDropbear' > /etc/default/dropbear
# My Dropbear Config
NO_START=0
DROPBEAR_PORT=PORT01
DROPBEAR_EXTRA_ARGS="-p PORT02"
DROPBEAR_BANNER="/etc/banner"
DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"
DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"
DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"
DROPBEAR_RECEIVE_WINDOW=65536
MyDropbear
systemctl restart dropbear

# Install Squid Proxy
cd
apt -y install squid3
cat > /etc/squid/squid.conf <<-END
acl manager proto cache_object
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 442
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
http_port 8181
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname Darknet
END
sed -i $MYIP2 /etc/squid/squid.conf

# Install Stunnel
apt -y install stunnel4
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
accept = 444
connect = 127.0.0.1:109
END

# Make Stunnel Certificate 
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# Configuration Stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

apt install privoxy -y
rm -f /etc/privoxy/config
# Creating Privoxy server config using cat eof tricks
cat <<'myPrivoxy' > /etc/privoxy/config
# My Privoxy Server Config
user-manual /usr/share/doc/privoxy/user-manual
confdir /etc/privoxy
logdir /var/log/privoxy
filterfile default.filter
logfile logfile
listen-address 0.0.0.0:25800
toggle 1
enable-remote-toggle 0
enable-remote-http-toggle 0
enable-edit-actions 0
enforce-blocks 0
buffer-limit 4096
enable-proxy-authentication-forwarding 1
forwarded-connect-retries 1
accept-intercepted-requests 1
allow-cgi-request-crunching 1
split-large-forms 0
keep-alive-timeout 5
tolerate-pipelining 1
socket-timeout 300
permit-access 0.0.0.0/0 xxxxxxxxx
myPrivoxy

sed -i $MYIP2 /etc/privoxy/config

systemctl start privoxy
systemctl enable privoxy
systemctl restart privoxy

# Install Iptable Persisten
apt -y install iptables iptables-persistent -y

wget https://raw.githubusercontent.com/vuneral/eco/main/module/installvpn.sh
chmod +x installvpn.sh
./installvpn.sh

wget https://raw.githubusercontent.com/vuneral/eco/main/module/clientvpn.sh
chmod +x clientvpn.sh
./clientvpn.sh

#IPV4 Fowarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

# Install Fail2ban
apt -y install fail2ban

# SSH/Dropbear Banner
wget -O /etc/banner "https://raw.githubusercontent.com/vuneral/eco/main/module/banner"
sed -i 's@#Banner none@Banner /etc/banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner"@g' /etc/default/dropbear

# Update BBR
wget https://raw.githubusercontent.com/dopekid30/AutoScriptDebian10/main/Resources/Other/bbr.sh && chmod +x bbr.sh && ./bbr.sh

# Install DDOS
cd
apt-get -y install dnsutils dsniff
wget https://raw.githubusercontent.com/dopekid30/AutoScriptDebian10/main/Resources/DDOS/ddos-deflate-master.zip
unzip ddos-deflate-master.zip
cd ddos-deflate-master
./install.sh
rm -rf /root/ddos-deflate-master.zip

# Some command to identify null shells when you tunnel through SSH or using Stunnel
sed -i '/\/bin\/false/d' /etc/shells
sed -i '/\/usr\/sbin\/nologin/d' /etc/shells
echo '/bin/false' >> /etc/shells
echo '/usr/sbin/nologin' >> /etc/shells

# Block Torrents
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

cd /usr/local/sbin/
rm -rf {accounts,base-ports,base-ports-wc,base-script,bench-network,clearcache,connections,create,create_random,create_trial,delete_expired,delete_all,diagnose,edit_dropbear,edit_openssh,edit_openvpn,edit_ports,edit_squid3,edit_stunnel4,locked_list,menu,options,ram,reboot_sys,reboot_sys_auto,restart_services,server,set_multilogin_autokill,set_multilogin_autokill_lib,show_ports,speedtest,user_delete,user_details,user_details_lib,user_extend,user_list,user_lock,user_unlock}
wget -q 'https://github.com/yue0706/parte/raw/main/fixed1.zip'
unzip -qq fixed1.zip
rm -f fixed1.zip
chmod +x ./*

# Purge Unnecessary Files
apt -y autoclean
apt -y remove --purge unscd
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove bind9*;
apt-get -y remove sendmail*

# Stop Nginx Port 80
service nginx stop

rm -f run.sh
clear
