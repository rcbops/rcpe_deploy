#!/bin/bash
mkdir /home/rcb/.ssh
chmod -R 700 /home/rcb/.ssh
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDb3qE8vjthnt9jtkXeMgr6OKHvIubXHwRjnp6FWlSFhVc0T7rLlU0VFhfD93jLnFTDj3Dt0jxH9CAvqZKVLYRs0Pad+iLI8gZ0A7Fy0+vENJMV8hX3Oj7uKXV5Wd0DO8pTQ+65vwZ9hYaA38r94PVGrbMYTgdfUH9oR5ALAWTplR6ZUq9JgsZc9LBjjGxjRTObS3coW4w9nvmpBFYkWWX6oO6HeLqdpkzp0bT2q07ymIjO+212a4nV+lkT0/5TuXsKbbnAAnYEixpFEUy0LKLWzsYR/DxwEFmonbWz1DMDM/qoUgqiRT0VqAgUYapeN2d4JtSKk4cwH41uAQIDRtb1 openstack@bastion' >> /home/rcb/.ssh/authorized_keys
chmod -R 600 /home/rcb/.ssh/authorized_keys
chown -R rcb:rcb /home/rcb/.ssh/
wget -O /home/rcb/install-crowbar http://172.31.0.6/install-crowbar
wget -O /home/rcb/network.json http://172.31.0.6/network.json
chown rcb:rcb /home/rcb/install-crowbar
chmod ug+x /home/rcb/install-crowbar
sed -i '/^exit/i /home/rcb/install-crowbar' /etc/rc.local &>/var/log/install-crowbar.log
cat > /etc/network/interfaces <<EOFNET
auto lo
iface lo inet loopback

auth eth0
iface eth0 inet manual
    post-up ifconfig eth0 up

auto br0
iface br0 inet static
    address 172.31.0.9
    netmask 255.255.255.0
    gateway 172.31.0.5
    bridge_ports eth0
    bridge_stp off
    bridge_maxwait 0
    bridge_fd 0

auto crowbarbr0 
iface crowbar0 inet static
    address 192.168.124.9
    netmask 255.255.255.0
    bridge_ports none
    bridge_fd 0
    bridge_stp off
    bridge_maxwait 0
EOFNET
echo 'nameserver 64.39.2.170' > /etc/resolv.conf
