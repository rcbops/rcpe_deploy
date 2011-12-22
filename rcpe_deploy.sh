#!/bin/bash
# NOTE: You must create a .creds file with DRAC USER and PASSWORD
SSH_OPTS='-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'

# Prepare bastion interface/iptables
echo "Setting up iptables and system forwarding for eth0.."
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sed -i 's/^#net.ipv4.ip_forward/net.ipv4.ip_forward/' /etc/sysctl.conf
sysctl -p /etc/sysctl.conf

# Check for/Generate ssh key
if [ ! -f ~/.ssh/id_rsa.pub ]; then
    ssh-keygen -t rsa -f ~/.ssh/id_rsa -N '' -q
fi

# Remove old deployrc
if [ -f .deployrc ]; then
    rm -rf .deployrc
fi

# Parse json file, extract bastion/pxeapp/infra/crowbar addresses, export to .deployrc
echo "Extracting json values to environment variables.."
for i in BASTION PXEAPP INFRA INFRA_MAC INFRA_DRAC CROWBAR NETMASK GATEWAY NAMESERVER; do  python -c "import json; import os; data = open('env.json');json_data = json.load(data); data.close(); print json_data['attributes']['network']['reserved']['$i'.lower()]" | echo "export $i=`awk '{print $0}'`" >> .deployrc; done

# Source .deployrc
source .deployrc

# Download pxeappliance image
echo "Downloading pxeappliance from cloud files.."
# wget -O /opt/rcb/pxeappliance.qcow2 http://c271871.r71.cf1.rackcdn.com/pxeappliance_gold.qcow2
# wget -O /opt/rcb/pxeappliance.xml http://c271871.r71.cf1.rackcdn.com/pxeappliance.xml

# Mount image
echo "Mounting pxeppliance qcow.."
modprobe nbd max_part=8
qemu-nbd -c /dev/nbd0 /opt/rcb/pxeappliance.qcow2
partprobe /dev/nbd0
sleep 10
mount /dev/nbd0p1 /mnt/pxeapp

# Fixup preseed and pxelinux.cfg/defaul to match environment
echo "Modifying infra node preseed with environment values.."
#sed -i "s/<nameserver>/${NAMESERVER}/" /mnt/pxeapp/srv/tftproot/pxelinux.cfg/default
#sed -i "s/<infra ip>/${INFRA}/" /mnt/pxeapp/srv/tftproot/pxelinux.cfg/default
#sed -i "s/<netmask>/${NETMASK}/" /mnt/pxeapp/srv/tftproot/pxelinux.cfg/default
#sed -i "s/<gateway>/${GATEWAY}/" /mnt/pxeapp/srv/tftproot/pxelinux.cfg/default
PUBKEY=`cat ~/.ssh/id_rsa.pub`
sed -i "/^#d-i preseed\/late_command string/a d-i preseed\/late_command string wget http:\/\/${PXEAPP}\/post_install.sh -O \/target\/root\/post_install.sh; chmod a+x \/target\/root\/post_install.sh; chroot \/target \/root\/post_install.sh" /mnt/pxeapp/var/www/preseed.txt
sed -i "s/<pxeapp>/${PXEAPP}/" /mnt/pxeapp/srv/tftproot/pxelinux.cfg/default

# Set Rackspace DNS in pxeappliance
echo "Setting pxeappliance nameserver.."
echo "nameserver 64.39.2.170" >> /mnt/pxeapp/etc/resolv.conf

# Create post_install.sh and move to apache dir for later..
cat >post_install.sh << EOF
#!/bin/bash
mkdir /home/rcb/.ssh
chmod -R 700 /home/rcb/.ssh
echo '${PUBKEY}' >> /home/rcb/.ssh/authorized_keys
chmod -R 644 /home/rcb/.ssh/authorized_keys
chown -R rcb:rcb /home/rcb/.ssh/
wget -O /home/rcb/install-crowbar http://${PXEAPP}/install-crowbar
wget -O /home/rcb/network.json http://${PXEAPP}/network.json
chown rcb:rcb /home/rcb/install-crowbar
chmod ug+x /home/rcb/install-crowbar
sed -i '/^exit/i /home/rcb/install-crowbar' /etc/rc.local
sed -i 's/dhcp/static/' /etc/network/interfaces
cat >>/etc/network/interfaces << END
    address ${INFRA}
    netmask ${NETMASK}
    gateway ${GATEWAY}
END
echo 'nameserver ${NAMESERVER}' > /etc/resolv.conf
EOF
cp post_install.sh /mnt/pxeapp/var/www/post_install.sh
cp network.json /mnt/pxeapp/var/www/network.json

# Copy crowbar install script to the apache dir for later..
cp install-crowbar /mnt/pxeapp/var/www/install-crowbar

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

dhcp-host=${INFRA_MAC},hostname,${INFRA}
EOF
mv /tmp/dnsmasq.conf /mnt/pxeapp/etc/dnsmasq.conf
rm -rf /tmp/dnsmasq.conf

# Unmount modified image
echo "Unmounting pxeappliance image.."
umount /mnt/pxeapp
qemu-nbd -d /dev/nbd0

# Register domain/ boot pxeapp
echo "Defining pxeappliance domain and starting appliance.."
virsh define /opt/rcb/pxeappliance.xml
virsh start pxeappliance

# IPMI infra node
source .creds
/usr/bin/ipmitool -H ${INFRA_DRAC} -U $DUSERNAME -P $DPASSWORD chassis bootdev pxe
POWERSTATE=`ipmitool -H ${INFRA_DRAC} -U $DUSERNAME -P $DPASSWORD chassis status | grep System | awk '{print $4}'`
if [ $POWERSTATE == 'on' ]; then
    for i in $(seq 1 5); do 
        /usr/bin/ipmitool -H ${INFRA_DRAC} -U $DUSERNAME -P $DPASSWORD chassis power cycle
    done
else
    for i in $(seq 1 5); do 
       /usr/bin/ipmitool -H ${INFRA_DRAC} -U $DUSERNAME -P $DPASSWORD chassis power on
    done
fi
sleep 10s

# WAIT FOR ADMIN NODE TO HAVE SSH
# This takes ~30 mins
count=1
while [ $count -lt 30 ]; do
    count=$(( count + 1 ))
    sleep 60s
    if ( nc ${INFRA} 22 -w 1 -q 0 < /dev/null ); then
        break
    fi
    if [ $count -eq 30 ]; then
        log "Server is not network accessible"
        exit 1
    fi
done

# Transfer Crowbar install script to admin node
ssh-keygen -f "/root/.ssh/known_hosts" -R 172.31.0.9
ssh -i ~/id_rsa.pub ${SSH_OPTS} rcb@${INFRA} 'ls -al'

# Destroy pxeappliance vm/domain
virsh destroy pxeappliance
virsh undefine pxeappliance
