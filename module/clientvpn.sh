# Initializing IP
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ifconfig.co);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID

# Creating our root directory for all of our .ovpn configs
rm -rf /var/www/openvpn
mkdir -p /var/www/openvpn

# Now creating all of our OpenVPN Configs 
cat <<EOF152> /var/www/openvpn/volt-tcp-1194.ovpn
# Volt Premium Script
# Owner Cyberbossz
client
dev tun
proto tcp
remote $MYIP 1194
remote-cert-tls server
tun-mtu 1500
mssfix 1450
auth-user-pass
auth none
cipher none
comp-lzo
setenv CLIENT_CERT 1
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF152
cat <<EOF16> /var/www/openvpn/volt-tcp-110.ovpn
# Volt Premium Script
# Owner Cyberbossz
client
dev tun
proto tcp
remote $MYIP 110
remote-cert-tls server
tun-mtu 1500
mssfix 1450
auth-user-pass
auth none
cipher none
comp-lzo
setenv CLIENT_CERT 1
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF16
cat <<EOF160> /var/www/openvpn/volt-udp-2500.ovpn
# Volt Premium Script
# Owner Cyberbossz
client
dev tun
proto udp
remote $MYIP 2500
remote-cert-tls server
tun-mtu 1500
mssfix 1450
auth-user-pass
auth none
cipher none
comp-lzo
setenv CLIENT_CERT 1
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF160
cat <<EOF17> /var/www/openvpn/volt-udp-2200.ovpn
# Volt Premium Script
# Owner Cyberbossz
client
dev tun
proto udp
remote $MYIP 2200
remote-cert-tls server
tun-mtu 1500
mssfix 1450
auth-user-pass
auth sha256
cipher AES-256-CBC
comp-lzo
setenv CLIENT_CERT 1
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF17
 cat <<EOF19> /var/www/openvpn/README.txt
# VOLTVPN NOTE
# DO NOT USE THE SERVER IN ANY ILLEGAL MATTER
# YOU KNOW WHAT WILL HAPPEN WHEN YOU DO THAT
For Updates, kindly follow our
Fb Page: t.me/cyberbossz
Telegram: https://t.me/cyberbossz
# Thank You For Your Support <3
EOF19

rm -f clientvpn.sh
