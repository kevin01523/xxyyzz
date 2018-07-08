#!/bin/bash
#

SERVER_IP=""
SERVER_PASSWORD=""
SHARED_KEY=""
USER=""

echo -n "Enter Server IP: "
read SERVER_IP
echo -n "Set VPN Username to create: "
read USER
read -s -p "Set VPN Password: " SERVER_PASSWORD
echo ""
read -s -p "Set IPSec Shared Keys: " SHARED_KEY
echo ""
echo "+++ Now sit back and wait until the installation finished +++"
HUB="VPNHUB"
HUB_PASSWORD=${SERVER_PASSWORD}
USER_PASSWORD=${SERVER_PASSWORD}
TARGET="/usr/local/"

# Update system
yum update

# Get build tools
yum -y groupinstall "Development Tools"
yum -y install nano cmake ncurses-devel openssl-devel readline-devel zlib-devel wget dnsmasq expect gcc  ncurses-devel epel-release
sleep 2
# Define softether version
RTM=$(curl http://www.softether-download.com/files/softether/ | grep -o 'v[^"]*e' | grep beta | tail -1)
IFS='-' read -r -a RTMS <<< "${RTM}"

# Get softether source
wget "http://www.softether-download.com/files/softether/${RTMS[0]}-${RTMS[1]}-${RTMS[2]}-${RTMS[3]}-${RTMS[4]}/Linux/SoftEther_VPN_Server/64bit_-_Intel_x64_or_AMD64/softether-vpnserver-${RTMS[0]}-${RTMS[1]}-${RTMS[2]}-${RTMS[3]}-linux-x64-64bit.tar.gz" -O /tmp/softether-vpnserver.tar.gz

# Extract softether source
tar -xzvf /tmp/softether-vpnserver.tar.gz -C /usr/local/

# Remove unused file
rm /tmp/softether-vpnserver.tar.gz

# Move to source directory
cd /usr/local/vpnserver

# Build softether
make i_read_and_agree_the_license_agreement

# Change file permission
chmod 0700 * && chmod +x vpnserver && chmod +x vpncmd

# Link binary files
#ln -s /usr/local/vpnserver/vpnserver /usr/local/bin/vpnserver
#ln -s /usr/local/vpnserver/vpncmd /usr/local/bin/vpncmd

# Add systemd service
cat <<EOF >/lib/systemd/system/vpnserver.service
[Unit]
Description=SoftEther VPN Server
After=network.target
ConditionPathExists=!/usr/local/vpnserver/do_not_run

[Service]
Type=forking
ExecStart=/usr/local/vpnserver/vpnserver start
ExecStartPost=/bin/sleep 3s
ExecStartPost=/sbin/ip address add 192.168.234.1/24 dev tap_vpn
ExecStop=/usr/local/vpnserver/vpnserver stop
KillMode=process
Restart=on-failure
WorkingDirectory=/usr/local/vpnserver

# Hardening
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=full
ReadOnlyDirectories=/
ReadWriteDirectories=-/usr/local/vpnserver
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_BROADCAST CAP_NET_RAW CAP_SYS_NICE CAP_SYS_ADMIN CAP_SETUID

[Install]
WantedBy=multi-user.target
EOF

# Act as router
echo net.ipv4.ip_forward = 1 | sudo tee -a /etc/sysctl.conf
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.d/ipv4_forwarding.conf
sysctl --system
sysctl -p


${TARGET}vpnserver/vpncmd localhost /SERVER /CMD ServerPasswordSet ${SERVER_PASSWORD}
sleep 2
${TARGET}vpnserver/vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD HubCreate ${HUB} /PASSWORD:${HUB_PASSWORD}
sleep 2
${TARGET}vpnserver/vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /HUB:${HUB} /CMD UserCreate ${USER} /GROUP:none /REALNAME:none /NOTE:none
sleep 2
${TARGET}vpnserver/vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /HUB:${HUB} /CMD UserPasswordSet ${USER} /PASSWORD:${USER_PASSWORD}
sleep 2
${TARGET}vpnserver/vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD IPsecEnable /L2TP:yes /L2TPRAW:yes /ETHERIP:yes /PSK:${SHARED_KEY} /DEFAULTHUB:${HUB}
sleep 2
${TARGET}vpnserver/vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD BridgeCreate ${HUB} /DEVICE:vpn /TAP:yes
sleep 2
${TARGET}vpnserver/vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD VpnOverIcmpDnsEnable /ICMP:yes /DNS:yes
sleep 2
${TARGET}vpnserver/vpncmd localhost /SERVER /PASSWORD:${SERVER_PASSWORD} /CMD HubDelete DEFAULT
sleep 2

# configure dnsmasq
cat <<EOF >> /etc/dnsmasq.conf
interface=tap_vpn
dhcp-range=tap_vpn,192.168.234.10,192.168.234.100,2h
dhcp-option=tap_vpn,option:router,192.168.234.1
port=0
dhcp-option=tap_vpn,option:dns-server,8.8.8.8,208.67.220.220
EOF

#secret
sed -i "s/DisableNatTraversal false/DisableNatTraversal true/g" /usr/local/vpnserver/vpn_server.config


IP=$(ip a s|grep -A8 -m1 MULTICAST|grep -m1 inet|cut -d' ' -f6|cut -d'/' -f1)

systemctl disable firewalld
yum -y install iptables-services
systemctl enable iptables
iptables -t nat -A POSTROUTING -s 192.168.234.0/24 -j SNAT --to-source ${IP}
service iptables save

# Reload service
systemctl daemon-reload
# Enable service
systemctl enable vpnserver
systemctl enable dnsmasq
# Start service
systemctl restart vpnserver
systemctl restart dnsmasq
systemctl restart iptables


# Init config vpnserver
# > cd /usr/local/vpnserver
# > ./vpncmd
# > ServerPasswordSet yourPassword
# Then use SoftEther VPN Server Manager to mange your server
echo "Softether server configuration has been done!"
echo " "
echo "Host: ${HOST}"
echo "Virtual Hub: ${HUB}"
echo "Username: ${USER}"
echo "Password: ${SERVER_PASSWORD}"
echo "Server Password: ${SE_PASSWORD}"

exit 0
