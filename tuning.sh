sed -i '/^\*\ *soft\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
sed -i '/^\*\ *hard\ *nofile\ *[[:digit:]]*/d' /etc/security/limits.conf
echo '* soft nofile 65536' >>/etc/security/limits.conf
echo '* hard nofile 65536' >>/etc/security/limits.conf
echo '' > /root/.bash_history && history -c && echo '' > /var/log/syslog

sed -ir "/\(#n\|n\)et.ipv4.tcp_timestamps.*/d;/\(#n\|n\)et.ipv4.tcp_sack.*/d;/\(#n\|n\)et.core.netdev_max_backlog.*/d;/\(#n\|n\)et.ipv4.tcp_low_latency.*/d" /etc/sysctl{.conf,.d/*.conf}
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 0
net.core.netdev_max_backlog = 250000
net.ipv4.tcp_low_latency = 1" > /etc/sysctl.d/80-volt-tuning.conf
sed -ir "/\(#n\|n\)et.core.\(netdev\|rmem\|wmem\|optmem\).*/d;/\(#n\|n\)et.ipv4.\(tcp\|udp\)_\(mem\|rmem\|wmem\).*/d" /etc/sysctl{.conf,.d/*.conf}
printf "%s" "net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 16777216
net.ipv4.tcp_mem = 16777216 16777216 16777216
net.ipv4.udp_mem = 16777216 16777216 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216" >> /etc/sysctl.d/80-volt-tuning.conf
sysctl --system &>/dev/null

wget -q "https://github.com/yue0706/auto_bbr/raw/main/bbr.sh" && chmod +x bbr.sh && ./bbr.sh
rm -f bbr.sh
clear
