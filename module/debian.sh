#!/bin/sh
#Premium Local Vpn Script
#Script By Volt Vpn

cat <<'EOFOpenSSH' > /etc/ssh/sshd_config
Port 22
Port 225
ListenAddress 0.0.0.0
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key
#KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
PermitRootLogin yes
StrictModes yes
#RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
#RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding yes
X11DisplayOffset 10
GatewayPorts yes
PrintMotd no
PrintLastLog yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
Banner /etc/banner
TCPKeepAlive yes
ClientAliveInterval 240
ClientAliveCountMax 2
UseDNS no
EOFOpenSSH

rm -rf /etc/apt/sources.list.d/openvpn*
echo "deb http://build.openvpn.net/debian/openvpn/stable $(lsb_release -sc) main" >/etc/apt/sources.list.d/openvpn.list && apt-key del E158C569 && wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
wget -qO security-openvpn-net.asc "https://keys.openpgp.org/vks/v1/by-fingerprint/F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7" && gpg --import security-openvpn-net.asc
#update
apt update -y
apt upgrade -y
apt dist-upgrade -y

# install wget and curl
apt -y install wget curl

# Removing some firewall tools that may affect other services
apt-get remove --purge ufw firewalld -y
#Install Component
apt-get install nano wget curl zip unzip tar gzip p7zip-full bc rc openssl cron net-tools dnsutils dos2unix screen bzip2 ccrypt -y
apt-get install openvpn dropbear stunnel4 privoxy ca-certificates nginx ruby apt-transport-https lsb-release squid3 screenfetch -y

# Installing a text colorizer
gem install lolcat

# Trying to remove obsolette packages after installation
apt-get autoremove -y

# My workaround code to remove `BAD Password error` from passwd command, it will fix password-related error on their ssh accounts.
sed -i '/password\s*requisite\s*pam_cracklib.s.*/d' /etc/pam.d/common-password
sed -i 's/use_authtok //g' /etc/pam.d/common-password

# initializing var
MYIP=`ifconfig eth0 | awk 'NR==2 {print $2}'`
MYIP2="s/xxxxxxxxx/$MYIP/g";
cd /root
wget "https://raw.githubusercontent.com/wangzki03/VPSauto/master/tool/plugin.tgz"
wget "https://raw.githubusercontent.com/wangzki03/VPSauto/master/tool/premiummenu.zip"

# set time UMT +8
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# go to root
cd

# Edit file /etc/systemd/system/rc-local.service
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

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

sed -i '$ i\echo "nameserver 208.67.222.222" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 208.67.220.220" >> /etc/resolv.conf' /etc/rc.local
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# install
apt-get --reinstall --fix-missing install -y bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip wget net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch git
echo "clear" >> .profile
echo "echo neofetch >> .profile
echo "echo ================" >> .profile
echo "echo Script By VoltVpn" >> .profile

# install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=843/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 844 "/g' /etc/default/dropbear

# update dropbear 2020
wget https://matt.ucc.asn.au/dropbear/releases/dropbear-2020.81.tar.bz2
bzip2 -cd dropbear-2020.81.tar.bz2 | tar xvf -
cd dropbear-2020.81
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart
cd

# install squid3
cat > /etc/squid/squid.conf <<-END
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
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
acl SSH dst xxxxxxxxx/32
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8000
http_port 8181
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname VoltVpn
END
sed -i $MYIP2 /etc/squid/squid.conf;

# setting dan install vnstat debian 64bit
apt-get -y install vnstat
systemctl start vnstat
systemctl enable vnstat
chkconfig vnstat on
chown -R vnstat:vnstat /var/lib/vnstat

# setting banner
rm /etc/issue.net
wget -O /etc/issue.net "https://raw.githubusercontent.com/vuneral/eco/main/module/banner"
sed -i 's@#Banner@Banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
service ssh restart
service dropbear restart

# Checking if openvpn folder is accidentally deleted or purged
if [[ ! -e /etc/openvpn ]]; then
 mkdir -p /etc/openvpn
fi

# Removing all existing openvpn server files
rm -rf /etc/openvpn/*

# Creating server.conf, ca.crt, server.crt and server.key
cat <<'myOpenVPNconf1' > /etc/openvpn/server_tcp.conf
# VOLNETVPN
port 1194
dev tun
proto tcp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/volt.crt
key /etc/openvpn/volt.key
dh /etc/openvpn/dh.pem
duplicate-cn
persist-tun
persist-key
persist-remote-ip
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4000
topology subnet
server 192.168.1.0 255.255.255.0
push "redirect-gateway def1"
keepalive 5 60
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"
myOpenVPNconf1

cat <<'myOpenVPNconf2' > /etc/openvpn/server_tcp1.conf
# VOLNETVPN
port 110
dev tun
proto tcp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/volt.crt
key /etc/openvpn/volt.key
dh /etc/openvpn/dh.pem
duplicate-cn
persist-tun
persist-key
persist-remote-ip
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4000
topology subnet
server 192.168.2.0 255.255.255.0
push "redirect-gateway def1"
keepalive 5 60
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"
myOpenVPNconf2

cat <<'myOpenVPNconf3' > /etc/openvpn/server_udp.conf
# VOLNETVPN
port 2522
dev tun
proto udp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/volt.crt
key /etc/openvpn/volt.key
dh /etc/openvpn/dh.pem
duplicate-cn
persist-tun
persist-key
persist-remote-ip
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4000
topology subnet
server 192.168.3.0 255.255.255.0
push "redirect-gateway def1"
keepalive 5 60
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"
myOpenVPNconf3

cat <<'myOpenVPNconf4' > /etc/openvpn/server_udp1.conf
# VOLNETVPN
port 2255
dev tun
proto udp
ca /etc/openvpn/ca.crt
cert /etc/openvpn/volt.crt
key /etc/openvpn/volt.key
dh /etc/openvpn/dh.pem
duplicate-cn
persist-tun
persist-key
persist-remote-ip
cipher none
ncp-disable
auth none
comp-lzo
tun-mtu 1500
reneg-sec 0
plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login
verify-client-cert none
username-as-common-name
max-clients 4000
topology subnet
server 192.168.4.0 255.255.255.0
push "redirect-gateway def1"
keepalive 5 60
status /etc/openvpn/tcp_stats.log
log /etc/openvpn/tcp.log
verb 2
script-security 2
socket-flags TCP_NODELAY
push "socket-flags TCP_NODELAY"
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"
myOpenVPNconf4

cat <<'EOF7'> /etc/openvpn/ca.crt
-----BEGIN CERTIFICATE-----
MIIDxjCCA02gAwIBAgIUHOYpgZtNLLVaLXdqWXPl2wXN7zAwCgYIKoZIzj0EAwIw
gasxCzAJBgNVBAYTAlBIMREwDwYDVQQIDAhCYXRhbmdhczEWMBQGA1UEBwwNQmF0
YW5nYXMgQ2l0eTEXMBUGA1UECgwOR2FtZXJzIFZQTiBIdWIxGTAXBgNVBAsMEFBo
Q29ybmVyLUdWUE5IVUIxFzAVBgNVBAMMDkdWUE5IVUItU2VydmVyMSQwIgYJKoZI
hvcNAQkBFhVpbWFwc3ljaG8yOEBnbWFpbC5jb20wIBcNMjEwMTI4MTM0NTI3WhgP
MjA4MDAzMTkxMzQ1MjdaMIGrMQswCQYDVQQGEwJQSDERMA8GA1UECAwIQmF0YW5n
YXMxFjAUBgNVBAcMDUJhdGFuZ2FzIENpdHkxFzAVBgNVBAoMDkdhbWVycyBWUE4g
SHViMRkwFwYDVQQLDBBQaENvcm5lci1HVlBOSFVCMRcwFQYDVQQDDA5HVlBOSFVC
LVNlcnZlcjEkMCIGCSqGSIb3DQEJARYVaW1hcHN5Y2hvMjhAZ21haWwuY29tMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEDY0BO/SRsYYGZy+PKyCf7jruD/Sanr2GrNxC
YQ8vzbUqKvyjP+wIQXBJ//Ba8bOJH3K2dtKh3hzbaDdxzSjCxG9W36YdBCXxbDl8
kWMNjugeNySZ4QgVm5mFEA4r4uEYo4IBLDCCASgwHQYDVR0OBBYEFOxhLQt+r3qA
q173jqObhxF3BnESMIHrBgNVHSMEgeMwgeCAFOxhLQt+r3qAq173jqObhxF3BnES
oYGxpIGuMIGrMQswCQYDVQQGEwJQSDERMA8GA1UECAwIQmF0YW5nYXMxFjAUBgNV
BAcMDUJhdGFuZ2FzIENpdHkxFzAVBgNVBAoMDkdhbWVycyBWUE4gSHViMRkwFwYD
VQQLDBBQaENvcm5lci1HVlBOSFVCMRcwFQYDVQQDDA5HVlBOSFVCLVNlcnZlcjEk
MCIGCSqGSIb3DQEJARYVaW1hcHN5Y2hvMjhAZ21haWwuY29tghQc5imBm00stVot
d2pZc+XbBc3vMDAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIBBjAKBggqhkjOPQQD
AgNnADBkAjAlVh2EtpofZcHyTPD6u/GrKCPvSPqdz2+6/ybXuXa+VRGzoTrQ3cRf
VZPAbgSqEskCMHnvJ9Pm/bGbaXQ6pLgYeUBWRr1wWPeXFVs4caKRpSzZC73dKFdZ
Al+0Oxso76FBPg==
-----END CERTIFICATE-----
EOF7
cat <<'EOF9'> /etc/openvpn/volt.crt
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            74:6e:46:3f:6b:45:3e:d4:f2:38:ba:4f:fb:74:31:c8
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: C=PH, ST=Batangas, L=Batangas City, O=Gamers VPN Hub, OU=PhCorner-GVPNHUB, CN=GVPNHUB-Server/emailAddress=imapsycho28@gmail.com
        Validity
            Not Before: Jan 28 13:49:05 2021 GMT
            Not After : Mar 19 13:49:05 2080 GMT
        Subject: C=PH, ST=Batangas, L=Batangas City, O=Gamers VPN Hub, OU=PhCorner-GVPNHUB, CN=GVPNHUB-Server/emailAddress=imapsycho28@gmail.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:58:ef:b8:3d:fb:4b:59:26:c4:99:c4:9d:a9:c0:
                    d5:2a:a8:b2:85:8c:c3:8b:bf:c8:c7:05:1a:0b:bb:
                    75:df:91:38:03:6b:a7:be:b5:c4:b9:81:0a:8e:8f:
                    75:63:72:7e:3c:9e:37:12:d8:5c:25:af:0c:25:9c:
                    5d:85:ce:96:91:9f:be:6f:0b:a8:06:a9:ad:18:cf:
                    f9:76:8a:24:10:b4:89:b7:00:9d:72:f8:70:00:8f:
                    de:4b:2e:35:77:cb:b4
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Subject Key Identifier: 
                03:62:1C:3D:ED:E9:5B:F2:A6:0F:41:37:AD:AE:BB:8A:86:2A:E1:12
            X509v3 Authority Key Identifier: 
                keyid:EC:61:2D:0B:7E:AF:7A:80:AB:5E:F7:8E:A3:9B:87:11:77:06:71:12
                DirName:/C=PH/ST=Batangas/L=Batangas City/O=Gamers VPN Hub/OU=PhCorner-GVPNHUB/CN=GVPNHUB-Server/emailAddress=imapsycho28@gmail.com
                serial:1C:E6:29:81:9B:4D:2C:B5:5A:2D:77:6A:59:73:E5:DB:05:CD:EF:30
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Subject Alternative Name: 
                DNS:GVPNHUB-Server
    Signature Algorithm: ecdsa-with-SHA256
         30:65:02:31:00:ea:63:07:9e:9f:ae:0a:bf:0e:c7:07:bc:e4:
         68:83:ea:5f:1a:af:11:f0:ef:47:a7:c7:42:eb:cd:d2:9e:76:
         00:9c:34:f7:aa:23:f9:2d:c3:39:a5:9a:19:a0:dc:32:f2:02:
         30:16:f9:d9:0d:46:e9:b4:f3:1a:18:e1:36:f3:e6:62:8c:2f:
         a5:77:30:30:6a:9c:4f:13:11:a9:69:68:21:8a:31:f1:dc:8a:
         56:44:81:c9:1e:f3:17:d2:e7:38:7c:c1:52
-----BEGIN CERTIFICATE-----
MIID8DCCA3agAwIBAgIQdG5GP2tFPtTyOLpP+3QxyDAKBggqhkjOPQQDAjCBqzEL
MAkGA1UEBhMCUEgxETAPBgNVBAgMCEJhdGFuZ2FzMRYwFAYDVQQHDA1CYXRhbmdh
cyBDaXR5MRcwFQYDVQQKDA5HYW1lcnMgVlBOIEh1YjEZMBcGA1UECwwQUGhDb3Ju
ZXItR1ZQTkhVQjEXMBUGA1UEAwwOR1ZQTkhVQi1TZXJ2ZXIxJDAiBgkqhkiG9w0B
CQEWFWltYXBzeWNobzI4QGdtYWlsLmNvbTAgFw0yMTAxMjgxMzQ5MDVaGA8yMDgw
MDMxOTEzNDkwNVowgasxCzAJBgNVBAYTAlBIMREwDwYDVQQIDAhCYXRhbmdhczEW
MBQGA1UEBwwNQmF0YW5nYXMgQ2l0eTEXMBUGA1UECgwOR2FtZXJzIFZQTiBIdWIx
GTAXBgNVBAsMEFBoQ29ybmVyLUdWUE5IVUIxFzAVBgNVBAMMDkdWUE5IVUItU2Vy
dmVyMSQwIgYJKoZIhvcNAQkBFhVpbWFwc3ljaG8yOEBnbWFpbC5jb20wdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAARY77g9+0tZJsSZxJ2pwNUqqLKFjMOLv8jHBRoLu3Xf
kTgDa6e+tcS5gQqOj3Vjcn48njcS2FwlrwwlnF2FzpaRn75vC6gGqa0Yz/l2iiQQ
tIm3AJ1y+HAAj95LLjV3y7SjggFZMIIBVTAJBgNVHRMEAjAAMB0GA1UdDgQWBBQD
Yhw97elb8qYPQTetrruKhirhEjCB6wYDVR0jBIHjMIHggBTsYS0Lfq96gKte946j
m4cRdwZxEqGBsaSBrjCBqzELMAkGA1UEBhMCUEgxETAPBgNVBAgMCEJhdGFuZ2Fz
MRYwFAYDVQQHDA1CYXRhbmdhcyBDaXR5MRcwFQYDVQQKDA5HYW1lcnMgVlBOIEh1
YjEZMBcGA1UECwwQUGhDb3JuZXItR1ZQTkhVQjEXMBUGA1UEAwwOR1ZQTkhVQi1T
ZXJ2ZXIxJDAiBgkqhkiG9w0BCQEWFWltYXBzeWNobzI4QGdtYWlsLmNvbYIUHOYp
gZtNLLVaLXdqWXPl2wXN7zAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQD
AgWgMBkGA1UdEQQSMBCCDkdWUE5IVUItU2VydmVyMAoGCCqGSM49BAMCA2gAMGUC
MQDqYween64Kvw7HB7zkaIPqXxqvEfDvR6fHQuvN0p52AJw096oj+S3DOaWaGaDc
MvICMBb52Q1G6bTzGhjhNvPmYowvpXcwMGqcTxMRqWloIYox8dyKVkSByR7zF9Ln
OHzBUg==
-----END CERTIFICATE-----
EOF9
cat <<'EOF10' > /etc/openvpn/volt.key
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCbbP09CnIUSkg7Y4qV
jl/Owf/AXFtDs+8E0moCX0L6lGREiHeGre9Wzziyg2qqS/ehZANiAARY77g9+0tZ
JsSZxJ2pwNUqqLKFjMOLv8jHBRoLu3XfkTgDa6e+tcS5gQqOj3Vjcn48njcS2Fwl
rwwlnF2FzpaRn75vC6gGqa0Yz/l2iiQQtIm3AJ1y+HAAj95LLjV3y7Q=
-----END PRIVATE KEY-----
EOF10
cat <<'EOF28' > /etc/openvpn/dh.pem
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEAlVC6TGc5lslb4j30NJ8VdH7iAmd3mM23FtYdgoz/wPzeWplDgnej
N39TK4pRfg2g3IdhtIdqgbgYFJveaxJhY1TOyaiwx5jHlq5mq2nPQtIQiOmk/LzZ
bxSuF+/kMDITbG04Ed6HQfTvUi2AAjM5w2S2CbiNB8fQp/ppCOekakkaHxxgLcc8
c0KP+6LkGAZM01IJIozNAqQ5k/uVC4MzkgE9EmSIz5a6p48k3WyJu2j8tBjQJuRb
z3pFYMzJx0RniuRVRRjIUF2hW6JLEQhqhTQZEDhnO7vW8rEcAfqwsaQ3sr8j7+FD
k/KPGLimSf3dMSKhb/T9JY7J96/lXiPUewIBAg==
-----END DH PARAMETERS-----
EOF28
cat <<'EOF29' > /etc/openvpn/ta.key
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
7e15f11cddf9604647bc0fe181f174c1
3f6a9ecda3a4f0d759b4cf1bc4e092a4
fffe34d9c5d98eaab6e19572cc0c4153
753c9446209b737de772f938090705fd
5151e51ae95248b30723542fcf71d9c3
d60a12a1e35dcd73e2ac3acffaf33763
0753eede6eecee0536e7165ca4525ba2
c16e1fbc38b5bc2259f5200baab1b1bb
66e32855aab2d4a1d9e898adbc8486dc
64d87e3b1a164fc54f125a04fa572796
0f888b16d409cd3785bd8086153485eb
3af1dac1fe1f11170af786e56283f305
dfff819a87fefca63dd88cee89d39089
04c871b897fb30c2c405bf1fd6fcdfea
babf56ffea17c525a94e1c403b742c29
d43e69d056f19f5ed6b91c6696271a44
-----END OpenVPN Static key V1-----
EOF29
cat <<'EOF30' > /etc/openvpn/CLIENT.key
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDD9JqzDjCtqrpDBtMM6
nkTbX+t8eq0U1qB5F3q6ykCm8E5gGrLLOQllP0nyFBZHGRyhZANiAASY+qLrArcf
EMIJ1Vc4RPrQS+XIirwXmB7Xj94ROlpHF38otKbYpJkKXXHdgIIKwYmmRK7MMNlt
4HWCg3YIzXdoC976X/5Y94sBii4b5lMm75btNVpOEEz5akG59J5j5hw=
-----END PRIVATE KEY-----
EOF30
cat <<'EOF31' > /etc/openvpn/CLIENT.crt
-----BEGIN CERTIFICATE-----
MIID1TCCA1ugAwIBAgIQP3A8M99pxRMyOIEH8ZoG/jAKBggqhkjOPQQDAjCBqzEL
MAkGA1UEBhMCUEgxETAPBgNVBAgMCEJhdGFuZ2FzMRYwFAYDVQQHDA1CYXRhbmdh
cyBDaXR5MRcwFQYDVQQKDA5HYW1lcnMgVlBOIEh1YjEZMBcGA1UECwwQUGhDb3Ju
ZXItR1ZQTkhVQjEXMBUGA1UEAwwOR1ZQTkhVQi1TZXJ2ZXIxJDAiBgkqhkiG9w0B
CQEWFWltYXBzeWNobzI4QGdtYWlsLmNvbTAgFw0yMTAxMjgxMzU5MTBaGA8yMDgw
MDMxOTEzNTkxMFowgasxCzAJBgNVBAYTAlBIMREwDwYDVQQIDAhCYXRhbmdhczEW
MBQGA1UEBwwNQmF0YW5nYXMgQ2l0eTEXMBUGA1UECgwOR2FtZXJzIFZQTiBIdWIx
GTAXBgNVBAsMEFBoQ29ybmVyLUdWUE5IVUIxFzAVBgNVBAMMDkdWUE5IVUItQ2xp
ZW50MSQwIgYJKoZIhvcNAQkBFhVpbWFwc3ljaG8yOEBnbWFpbC5jb20wdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAASY+qLrArcfEMIJ1Vc4RPrQS+XIirwXmB7Xj94ROlpH
F38otKbYpJkKXXHdgIIKwYmmRK7MMNlt4HWCg3YIzXdoC976X/5Y94sBii4b5lMm
75btNVpOEEz5akG59J5j5hyjggE+MIIBOjAJBgNVHRMEAjAAMB0GA1UdDgQWBBQ7
k1OI68EH8CWjQ0EyeIVF7fewGDCB6wYDVR0jBIHjMIHggBTsYS0Lfq96gKte946j
m4cRdwZxEqGBsaSBrjCBqzELMAkGA1UEBhMCUEgxETAPBgNVBAgMCEJhdGFuZ2Fz
MRYwFAYDVQQHDA1CYXRhbmdhcyBDaXR5MRcwFQYDVQQKDA5HYW1lcnMgVlBOIEh1
YjEZMBcGA1UECwwQUGhDb3JuZXItR1ZQTkhVQjEXMBUGA1UEAwwOR1ZQTkhVQi1T
ZXJ2ZXIxJDAiBgkqhkiG9w0BCQEWFWltYXBzeWNobzI4QGdtYWlsLmNvbYIUHOYp
gZtNLLVaLXdqWXPl2wXN7zAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwCwYDVR0PBAQD
AgeAMAoGCCqGSM49BAMCA2gAMGUCMQCcX8H4y/yh0FX+KfMlr0pddojAMgDxDzcL
5VfOMho4C3M391KsvzQX2NBkays6k+ICMEzaiI32hS2zvkspVCAsSANl/4nxKSdG
FPFq6nTFawZekRJycKDCTCXDXUaCpIXbAw==
-----END CERTIFICATE-----
EOF31

# Getting some OpenVPN plugins for unix authentication
wget -qO /etc/openvpn/b.zip 'https://github.com/vuneral/eco/raw/main/module/openvpn_plugin64'
unzip -qq /etc/openvpn/b.zip -d /etc/openvpn
rm -f /etc/openvpn/b.zip

# Creating a New update message in server.conf
cat <<'NUovpn' > /etc/openvpn/server.conf
# New Update are now released, OpenVPN Server
# are now running both TCP and UDP Protocol. (Both are only running on IPv4)
# But our native server.conf are now removed and divided
# Into two different configs base on their Protocols:
#  * OpenVPN TCP (located at /etc/openvpn/server_tcp.conf
#  * OpenVPN UDP (located at /etc/openvpn/server_udp.conf
# 
# Also other logging files like
# status logs and server logs
# are moved into new different file names:
#  * OpenVPN TCP Server logs (/etc/openvpn/tcp.log)
#  * OpenVPN UDP Server logs (/etc/openvpn/udp.log)
#  * OpenVPN TCP Status logs (/etc/openvpn/tcp_stats.log)
#  * OpenVPN UDP Status logs (/etc/openvpn/udp_stats.log)
#
# Server ports are configured base on env vars
# executed/raised from this script (OpenVPN_TCP_Port/OpenVPN_UDP_Port)
#
# Enjoy the new update
# Script Updated by VoltVpn
NUovpn
 
# Some workaround for OpenVZ machines for "Startup error" openvpn service
if [[ "$(hostnamectl | grep -i Virtualization | awk '{print $2}' | head -n1)" == 'openvz' ]]; then
sed -i 's|LimitNPROC|#LimitNPROC|g' /lib/systemd/system/openvpn*
systemctl daemon-reload
fi

# Allow IPv4 Forwarding
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn.conf && sysctl --system &> /dev/null && echo 1 > /proc/sys/net/ipv4/ip_forward

# Configure Stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
openssl req -new -newkey rsa:2048 -days 9999 -nodes -x509 -sha256 -subj '/CN=127.0.0.1/O=localhost/C=MY' -keyout /etc/stunnel/stunnel.pem -out /etc/stunnel/stunnel.pem
cat > /etc/stunnel/stunnel.conf <<-END
sslVersion = all
pid = /stunnel.pid
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
client = no
[openvpn]
accept = 4433
connect = 127.0.0.1:1194
cert = /etc/stunnel/stunnel.pem
[dropbear]
accept = 444
connect = 127.0.0.1:109
cert = /etc/stunnel/stunnel.pem
END

# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf

# Resolve ANU
ANU=$(ip -o $ANU -4 route show to default | awk '{print $5}');

# TCP & UDP 
iptables -t nat -I POSTROUTING -s 192.168.1.0/24 -o $ANU -j MASQUERADE
iptables -t nat -I POSTROUTING -s 192.168.2.0/24 -o $ANU -j MASQUERADE
iptables -t nat -I POSTROUTING -s 192.168.3.0/24 -o $ANU -j MASQUERADE
iptables -t nat -I POSTROUTING -s 192.168.4.0/24 -o $ANU -j MASQUERADE
iptables-save > /etc/iptables.up.rules
chmod +x /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# Restore Iptables
cat > /etc/network/if-up.d/iptables <<-END
iptables-restore < /etc/iptables.up.rules
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o $ANU -j SNAT --to xxxxxxxxx
iptables -t nat -A POSTROUTING -s 192.168.2.0/24 -o $ANU -j SNAT --to xxxxxxxxx
iptables -t nat -A POSTROUTING -s 192.168.3.0/24 -o $ANU -j SNAT --to xxxxxxxxx
iptables -t nat -A POSTROUTING -s 192.168.4.0/24 -o $ANU -j SNAT --to xxxxxxxxx
END
sed -i $MYIP2 /etc/network/if-up.d/iptables
chmod +x /etc/network/if-up.d/iptables

# Starting OpenVPN server
systemctl start openvpn@server_tcp
systemctl start openvpn@server_tcp1
systemctl start openvpn@server_udp
systemctl start openvpn@server_udp1
systemctl enable openvpn@server_tcp
systemctl enable openvpn@server_tcp1
systemctl enable openvpn@server_udp
systemctl enable openvpn@server_udp1
systemctl restart openvpn@server_tcp
systemctl restart openvpn@server_tcp1
systemctl restart openvpn@server_udp
systemctl restart openvpn@server_udp1

cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/vuneral/eco/main/module/nginx.conf"
cat <<'myNginxC' > /etc/nginx/vps.conf
server {
  listen       88;
  server_name  127.0.0.1 localhost;
  access_log /var/log/nginx/vps-access.log;
  error_log /var/log/nginx/vps-error.log error;
  root   /var/www/openvpn;

  location / {
    index  index.html index.htm index.php;
    try_files $uri $uri/ /index.php?$args;
  }

  location ~ \.php$ {
    include /etc/nginx/fastcgi_params;
    fastcgi_pass  127.0.0.1:9000;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  }
}
myNginxC
/etc/init.d/nginx restart

mkdir -p /var/www/openvpn

# Now creating all of our OpenVPN Configs 
cat <<EOF152> /var/www/openvpn/tcp-01.ovpn
# TCP KCP Openvpn
# VoltNetVpn
client
dev tun
proto tcp
remote xxxxxxxxx 1194
remote-cert-tls server
tun-mtu 1500
mssfix 1450
auth-user-pass
auth none
cipher none
comp-lzo
setenv CLIENT_CERT 0
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF152

# Now creating all of our OpenVPN Configs 
cat <<EOF555> /var/www/openvpn/tcp-02.ovpn
# TCP KCP Openvpn
# VoltNetVpn
client
dev tun
proto tcp
remote xxxxxxxxx 110
remote-cert-tls server
tun-mtu 1500
mssfix 1450
auth-user-pass
auth none
cipher none
comp-lzo
setenv CLIENT_CERT 0
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF555

# Now creating all of our OpenVPN Configs 
cat <<EOF666> /var/www/openvpn/udp-01.ovpn
# UDP KCP Openvpn
# VoltNetVpn
client
dev tun
proto udp
remote xxxxxxxxx 2522
remote-cert-tls server
tun-mtu 1500
mssfix 1450
auth-user-pass
auth none
cipher none
comp-lzo
setenv CLIENT_CERT 0
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF666

# Now creating all of our OpenVPN Configs 
cat <<EOF777> /var/www/openvpn/udp-02.ovpn
# UDP KCP Openvpn
# VoltNetVpn
client
dev tun
proto udp
remote xxxxxxxxx 2255
remote-cert-tls server
tun-mtu 1500
mssfix 1450
auth-user-pass
auth none
cipher none
comp-lzo
setenv CLIENT_CERT 0
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
EOF777

sed -i $MYIP2 /var/www/openvpn/tcp-01.ovpn;
sed -i $MYIP2 /var/www/openvpn/tcp-02.ovpn;
sed -i $MYIP2 /var/www/openvpn/udp-01.ovpn;
sed -i $MYIP2 /var/www/openvpn/udp-02.ovpn;

# Creating all .ovpn config archives
cd /var/www/openvpn 
zip -qq -r OVPN.zip *.ovpn *.txt
cd

iptables -A INPUT -s $(wget -4qO- http://ipinfo.io/ip) -p tcp -m multiport --dport 1:65535 -j ACCEPT

# Configure menu
apt-get install unzip
cd /usr/local/bin/
wget "https://raw.githubusercontent.com/wangzki03/VPSauto/master/tool/premiummenu.zip" 
unzip premiummenu.zip
chmod +x /usr/local/bin/*

# add eth0 to vnstat
vnstat -u -i eth0

# compress configs
cd /home/vps/public_html
zip configs.zip client.ovpn OpenVPN-Stunnel.ovpn stunnel.conf

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

# install fail2ban
apt -y install fail2ban

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# blockir torrent
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

# xml parser
cd
apt install -y libxml-parser-perl

# remove unnecessary files
apt -y autoclean
apt -y remove --purge unscd
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove bind9*;
apt-get -y remove sendmail*
apt -y autoremove

# finishing
cd
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/stunnel4 restart
/etc/init.d/vnstat restart
/etc/init.d/squid restart

history -c
echo "unset HISTFILE" >> /etc/profile

#clearing history
history -c
rm -f debian.sh
cd /root
# info
clear
echo " "
echo "Installation local vpn has been completed!!"
echo "DEVICE WILL SLEEP IN 10 SECONDS"
echo "PLEASE WAIT PATIENTLY FOR OTHER INSTALLATION"
echo " "
echo "--------------------------- Configuration Setup Local Vpn -------------------------"
echo "                            Local Vpn Module Installation                           "
echo "                                  Script By VoltVpn                        "
echo "--------------------------------------------------------------------------------"
sleep 10
clear
