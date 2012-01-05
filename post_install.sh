#!/bin/bash
mkdir /home/rcb/.ssh
chmod -R 700 /home/rcb/.ssh
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDvG8C1+J4rHevQ94Rpp82Fm9bd724MW9JDLXzbAkhntDO3Zb9NjG07pn12vzFs32TBv69HD8fcRM/OBd2qVAJpD7zBskj1zXkJIc/8VjyOKPpMSdH5oX8TVMUOo3+d13RhCXwPju6pq9JL1L2gUUxcaPJshzn91ngAqsKGBn1HYCb6BooMNGS++okXhDOmrULIbJ02q+sp4gg6WKIPL0MZB/VA5sjPx+ONAuXUYJK6sczJV015prYiL9Q3v921qFS4NVEAvyDJOLo3A79u/2cggHxFGe5y8cCBj9ny3BYfgkG6+8WjxlXNbfmAHMjY8EtP4rLtuWJxU5/aYxv4G5ox openstack@bastion' >> /home/rcb/.ssh/authorized_keys
chmod -R 600 /home/rcb/.ssh/authorized_keys
chown -R rcb:rcb /home/rcb/.ssh/
wget -O /home/rcb/install-crowbar http://172.31.0.6/install-crowbar
wget -O /home/rcb/network.json http://172.31.0.6/network.json
chown rcb:rcb /home/rcb/install-crowbar
chmod ug+x /home/rcb/install-crowbar
sed -i '/^exit/i /bin/bash /home/rcb/install-crowbar' /etc/rc.local &>/var/log/install-crowbar.log
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
iface crowbarbr0 inet static
    address 192.168.125.9
    netmask 255.255.255.0
    bridge_ports none
    bridge_fd 0
    bridge_stp off
    bridge_maxwait 0
EOFNET
echo 'nameserver 64.39.2.170' > /etc/resolv.conf
