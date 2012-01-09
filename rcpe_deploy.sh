#!/bin/bash

# set -e
# set -x

# remove me when done tsting
# PXE_IMAGE_URL=file:///opt/rcb/pxeappliance-dist.qcow2
#PXE_XML_URL=file:///opt/rcb/pxeappliance-dist.xml

PXE_IMAGE_URL=${PXE_IMAGE_URL:-http://c271871.r71.cf1.rackcdn.com/pxeappliance_gold.qcow2}
PXE_XML_URL=${PXE_XML_URL:-http://c271871.r71.cf1.rackcdn.com/pxeappliance.xml}

# NOTE: You must create a .creds file with DRAC USER and PASSWORD
SSH_OPTS='-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'

# Prepare bastion interface/iptables
echo "Setting up iptables and system forwarding for eth0.."
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sed -i 's/^#net.ipv4.ip_forward/net.ipv4.ip_forward/' /etc/sysctl.conf
sysctl -p /etc/sysctl.conf

# Check for/Generate ssh key
echo "Generating ssh keys.."
if [ ! -f /home/${SUDO_USER}/.ssh/id_rsa.pub ]; then
    ssh-keygen -t rsa -f /home/${SUDO_USER}/.ssh/id_rsa -N '' -q
fi

chown -R ${SUDO_USER}:${SUDO_USER} /home/${SUDO_USER}/.ssh
chmod -R go-rwx /home/${SUDO_USER}/.ssh

# Remove old deployrc
if [ -f .deployrc ]; then
    rm -rf .deployrc
fi

# Parse json file, extract bastion/pxeapp/infra/crowbar addresses, export to .deployrc
echo "Extracting json values to environment variables.."
for i in BASTION PXEAPP INFRA INFRA_MAC INFRA_DRAC CROWBAR NETMASK GATEWAY NAMESERVER CBFQDN NODECOUNT; do  python -c "import json; import os; data = open('env.json');json_data = json.load(data); data.close(); print json_data['attributes']['network']['reserved']['$i'.lower()]" | echo "export $i=`awk '{print $0}'`" >> .deployrc; done

# Source .deployrc
source .deployrc

# Install necessary packages
echo "Installing Packages.."
apt-get install -y libvirt-bin ipmitool curl qemu-kvm

# Download pxeappliance image
echo "Downloading pxeappliance from cloud files.."
mkdir -p /opt/rcb
mkdir -p /mnt/pxeapp
curl -o /opt/rcb/pxeappliance-dist.qcow2 ${PXE_IMAGE_URL}
curl -o /opt/rcb/pxeappliance.xml ${PXE_XML_URL}

# Mount image
echo "Mounting pxeppliance qcow.."
modprobe nbd max_part=8
modprobe kvm
modprobe kvm_intel
qemu-nbd -c /dev/nbd0 /opt/rcb/pxeappliance-dist.qcow2

sleep 3

if [ ! -e /dev/nbd0p1 ]; then
    partprobe /dev/nbd0
fi

sleep 3

mount /dev/nbd0p1 /mnt/pxeapp

# Fixup preseed and pxelinux.cfg/defaul to match environment
echo "Modifying infra node preseed with environment values.."
sed -i "s/<nameserver>/${NAMESERVER}/" /mnt/pxeapp/srv/tftproot/pxelinux.cfg/default
sed -i "s/<infra ip>/${INFRA}/" /mnt/pxeapp/srv/tftproot/pxelinux.cfg/default
sed -i "s/<netmask>/${NETMASK}/" /mnt/pxeapp/srv/tftproot/pxelinux.cfg/default
sed -i "s/<gateway>/${GATEWAY}/" /mnt/pxeapp/srv/tftproot/pxelinux.cfg/default
PUBKEY=`cat /home/${SUDO_USER}/.ssh/id_rsa.pub`
sed -i "/^#d-i preseed\/late_command string/a d-i preseed\/late_command string wget http:\/\/${PXEAPP}\/post_install.sh -O \/target\/root\/post_install.sh; chmod a+x \/target\/root\/post_install.sh; chroot \/target \/root\/post_install.sh" /mnt/pxeapp/var/www/preseed.txt
sed -i "s/<pxeapp>/${PXEAPP}/" /mnt/pxeapp/srv/tftproot/pxelinux.cfg/default

# Set Rackspace DNS in pxeappliance
echo "Setting pxeappliance nameserver.."
echo "nameserver 64.39.2.170" >> /mnt/pxeapp/etc/resolv.conf

# Create post_install.sh and move to apache dir for later..
echo "Creating post_install script for admin/infra node.."
cat >post_install.sh << EOF
#!/bin/bash
mkdir /home/rcb/.ssh
chmod -R 700 /home/rcb/.ssh
echo '${PUBKEY}' >> /home/rcb/.ssh/authorized_keys
chmod -R 600 /home/rcb/.ssh/authorized_keys
chown -R rcb:rcb /home/rcb/.ssh/
wget -O /home/rcb/install-crowbar http://${PXEAPP}/install-crowbar
wget -O /home/rcb/network.json http://${PXEAPP}/network.json
wget -O /home/rcb/firstboot.sh http://${PXEAPP}/firstboot.sh
chown rcb:rcb /home/rcb/install-crowbar
chmod ug+x /home/rcb/install-crowbar
sed -i '/^exit/i /bin/bash /home/rcb/install-crowbar >> /var/log/install-crowbar.log 2>&1' /etc/rc.local
cat > /etc/network/interfaces <<EOFNET
auto lo
iface lo inet loopback

auth eth0
iface eth0 inet manual
    post-up ifconfig eth0 up

auto br0
iface br0 inet static
    address ${INFRA}
    netmask ${NETMASK}
    gateway ${GATEWAY}
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
echo 'nameserver ${NAMESERVER}' > /etc/resolv.conf
EOF

# Crowbar Appliance firstboot 
echo "Generating firstboot script for crowbar head node.."
cat >firstboot.sh << EOF
#!/bin/bash
mkdir /home/crowbar/.ssh
echo '${PUBKEY}' >> /home/crowbar/.ssh/authorized_keys
chown -R 1000:1000 /home/crowbar/.ssh
chmod -R 0700 /home/crowbar/.ssh

# INSTALL CROWBAR
./tftpboot/ubuntu_dvd/extra/install ${CBFQDN}

# REMOVE FIRSTBOOT
chmod -R a+r /etc/gemrc
sed -i '/\/tftpboot\/ubuntu_dvd\/extra\/firstboot.sh/d' /etc/rc.local
EOF

echo "Putting scripts in place.."
cp post_install.sh /mnt/pxeapp/var/www/post_install.sh
cp network.json /mnt/pxeapp/var/www/network.json
cp firstboot.sh /mnt/pxeapp/var/www/firstboot.sh

# Copy crowbar install script to the apache dir for later..
cp install-crowbar /mnt/pxeapp/var/www/install-crowbar

# Fix up the install-crowbar
sed -i "s/<nameserver>/${NAMESERVER}/" /mnt/pxeapp/var/www/install-crowbar
sed -i "s/<crowbar>/${CROWBAR}/" /mnt/pxeapp/var/www/install-crowbar
sed -i "s/<netmask>/${NETMASK}/" /mnt/pxeapp/var/www/install-crowbar
sed -i "s/<gateway>/${GATEWAY}/" /mnt/pxeapp/var/www/install-crowbar

# Insert eth0 configuration into /etc/network/interfaces
echo "Modifying pxeappliance network interfaces.."
cat /mnt/pxeapp/etc/network/interfaces >> /tmp/interfaces
cat >>/tmp/interfaces << EOF
auto eth0
iface eth0 inet static
    address ${PXEAPP}
    netmask ${NETMASK}
    gateway ${BASTION}
EOF
mv /tmp/interfaces /mnt/pxeapp/etc/network/interfaces
rm -rf /tmp/interfaces

# Create dnsmasq.conf
echo "Setting up pxeappliance dnsmasq.."
cat >/tmp/dnsmasq.conf << EOF
dhcp-ignore=tag:!known
dhcp-ignore-names

dhcp-range=${PXEAPP},static,24h,tag:known
dhcp-option=3,${GATEWAY}
dhcp-option-force=208,f1:00:74:7e
dhcp-option-force=210,/
dhcp-option-force=211,30
dhcp-boot=pxelinux.0

enable-tftp
tftp-root=/srv/tftproot

dhcp-host=${INFRA_MAC},adminnode,${INFRA}
EOF
mv /tmp/dnsmasq.conf /mnt/pxeapp/etc/dnsmasq.conf
rm -rf /tmp/dnsmasq.conf

# Turn off ipv6 (seems to cause some dnsmasq problems)
cat > /mnt/pxeapp/etc/modprobe.d/00local.conf <<EOF
install ipv6 /bin/true
alias net-pf-10 off
alias ipv6 off
EOF

sed -i /mnt/pxeapp/boot/grub/grub.cfg -e 's#quiet$#quiet ipv6.disable=1#'

# Unmount modified image
echo "Unmounting pxeappliance image.."
umount /mnt/pxeapp
qemu-nbd -d /dev/nbd0

# Restart libvirt-bin to avoid hvm errors..
echo "Restart libvirt-bin.."
/etc/init.d/libvirt-bin restart

# Register domain/ boot pxeapp
echo "Defining pxeappliance domain and starting appliance.."
virsh define /opt/rcb/pxeappliance.xml
virsh start pxeappliance

# IPMI infra node
echo "PXE boot admin/infra node.."
source .creds
POWERSTATE=`ipmitool -H ${INFRA_DRAC} -U $DUSERNAME -P $DPASSWORD chassis status | grep System | awk '{print $4}'`
if [ $POWERSTATE == 'on' ]; then
    for i in $(seq 1 5); do 
        /usr/bin/ipmitool -H ${INFRA_DRAC} -U $DUSERNAME -P $DPASSWORD chassis bootdev pxe
        /usr/bin/ipmitool -H ${INFRA_DRAC} -U $DUSERNAME -P $DPASSWORD chassis power cycle
    done
else
    for i in $(seq 1 5); do 
       /usr/bin/ipmitool -H ${INFRA_DRAC} -U $DUSERNAME -P $DPASSWORD chassis bootdev pxe
       /usr/bin/ipmitool -H ${INFRA_DRAC} -U $DUSERNAME -P $DPASSWORD chassis power on
    done
fi
sleep 10s

# WAIT FOR ADMIN NODE TO HAVE SSH
# This takes ~30 mins
echo "Waiting for admin node to be accessible.."
count=1
while [ $count -lt 30 ]; do
    count=$(( count + 1 ))
    sleep 60s
    if ( nc ${INFRA} 22 -w 1 -q 0 < /dev/null ); then
        break
    fi
    if [ $count -eq 30 ]; then
        log "Admin/Infra node is not network accessible"
        exit 1
    fi
done

# Destroy pxeappliance vm/domain
virsh destroy pxeappliance
virsh undefine pxeappliance

# WAIT FOR CROWBAR NODE TO BE RESPONSIVE
# Giving ~30 minutes
echo "Waiting for crowbar installation.."
count=1
while [ $count -lt 30 ]; do
    count=$((count +1))
    sleep 60s
    if ( nc ${CROWBAR} 3000 -w 1 -q 0 < /dev/null ); then
        break
    fi
    if [ $count -eq 30 ]; then
        log "Crowbar vm did not come up."
        exit 1
    fi
done

# Since all nodes should be sitting in PXE we will wait a maximum of 30 minutes for all nodes to register
echo "Waiting for all crowbar managed nodes to register.."
count=1
while [ $count -lt 30 ]; do 
    count=$((count +1))
    sleep 60s
    ELEMENTS=`ssh -lcrowbar 172.31.0.10 "/opt/dell/bin/crowbar_crowbar -U crowbar -P crowbar elements | wc -l"`
    if ( ${ELEMENTS} == ${NODECOUNT} ); then
        break
    fi
    if [ $count -eq 30 ]; then
        log "Some crowbar nodes did not come up."
        exit 1
    fi
done 
