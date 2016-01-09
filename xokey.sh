#!/bin/bash
# Note you  NEED to configure these first few lines

# set path to usual locations where the 'ip' 'dig' or 'iptables' files are at
PATH=$PATH:/sbin/:/usr/sbin:/usr/bin:/bin:/usr/local/bin

IP_BIN=`which ip`
if [[ $? -ne 0 ]]; then
	echo "ERROR:  'ip' utility is not available";
	echo "On debian/ubuntu systems install the 'iproute2' package. sudo apt-get install iproute2";
	exit 1
fi

DIG_BIN=`which dig`
if [[ $? -ne 0 ]]; then
	echo "ERROR:  'dig' utility is not available";
	echo "On debian/ubuntu systems install the 'dnsutils' package. sudo apt-get install dnsutils";
	exit 1
fi

IPT_BIN=`which iptables`
if [[ $? -ne 0 ]]; then
	echo "ERROR:  'iptables' utility is not available";
	echo "On debian/ubuntu systems install the 'iptables' package. sudo apt-get install iptables";
	exit 1
fi

#Your home or office gateway IP addres
GATEWAY_IP=$(ip route | awk '/default/ { print $3 }'|head -n1)

#if the above gateway IP address doens't work manually it it below
#GATEWAY_IP=192.168.1.1

# Your remote XONet  DDNS IP address
XONET_IP=`dig +short 5621179daa536149-xon.vpex.org | awk '{ print $1 }' |head -n1`


#This is our USB ethernet interface.  Change if different on your system
XOKEY_ETH=usb0



#print out debug info
echo "GATEWAY_IP=$GATEWAY_IP   XONET_IP=$XONET_IP  XOKEY_ETH=$XOKEY_ETH"

###  There should be no need for you to edit below this line. 

function Print_Usage {
        echo "You must call the script with 'configip',  'route'  or 'unroute"
	exit
}

function Config_IP {
	echo "Configuring IP address and NAT"

	# enable IP forwarding
	echo 1 > /proc/sys/net/ipv4/ip_forward

	# attempt to delete if already exists.  Ignore errors. 
	iptables -t nat -D POSTROUTING -s 192.168.255.0/30  &> /dev/null

	# add masquerade rule
	iptables -t nat -I POSTROUTING 1 -s 192.168.255.0/30 -j MASQUERADE

	while [ 1 ]
	do
	        ip addr show dev $XOKEY_ETH > /dev/null 2>&1
	        NFOUND=$?
	        if [ $NFOUND -eq 0 ]
	        then
	                #device is there
	                ip addr flush dev $XOKEY_ETH
	                ip addr add 192.168.255.2/30  brd 192.168.255.3 dev $XOKEY_ETH  &&  ip link set $XOKEY_ETH up
	                break
	        else
	                echo "XOkey $XOKEY_ETH not detected yet waiting"
	        fi
	        sleep 1
	done

	echo "SUCCESS. You should now see the USB device UP and with a IP Address"
	echo
	ip addr show dev $XOKEY_ETH 
	echo
	echo "You can now point your web browser to https://192.168.255.1/"
	echo "After you login to the XOKey, connect to the XOnet, then run the next script"

	exit 0
}



if [ "$#" == "0" ]; then
	Print_Usage
	exit 1
fi

ARG=$1

if [ $ARG == "configip"  ]; then
	Config_IP
elif  [ $ARG == "route"  ]; then
	echo "adding route"
	ip route add $XONET_IP via $GATEWAY_IP
	ip route add 0.0.0.0/1 via 192.168.255.1
	ip route add 128.0.0.0/1 via 192.168.255.1

elif  [ $ARG == "unroute"  ]; then
	echo "removing routes"
	ip route del $XONET_IP via $GATEWAY_IP
	ip route del 0.0.0.0/1 via 192.168.255.1
	ip route del 128.0.0.0/1 via 192.168.255.1

else
	echo "Invalid Arg: $ARG"
	Print_Usage
fi


