#!/bin/sh

NR_PEERS=8
BRIDGE_NAME=br0
CONFIG_DIR=`pwd`

run_quagga() {
    local docker_name=q$1
    docker run --privileged=true -v $CONFIG_DIR/$docker_name:/etc/quagga --name $docker_name -id osrg/quagga
    sudo pipework $BRIDGE_NAME $docker_name 10.0.0.$1/16
}

stop_quagga() {
    local docker_name=q$1
    docker rm -f $docker_name
}

delete_bridge() {
    local name=$1
    local sysfs_name=/sys/class/net/$name
    if [ -e $sysfs_name ]; then
        sudo ifconfig $name down
        sudo brctl delbr $name
    fi
}

while getopts c:n: OPT
do
    case $OPT in
	c) CONFIG_DIR="$OPTARG"
	    ;;
	n) NR_PEERS="$OPTARG"
	    ;;
	*) echo "Unknown option"
	    exit 1
	    ;;
    esac
done

shift $((OPTIND - 1))

case "$1" in
    start)
	i=1
	while [ $i -le $NR_PEERS ]
	do
	    run_quagga $i
	    i=$(( i+1 ))
	done
	sudo ip addr add 10.0.255.1/16 dev $BRIDGE_NAME
	;;

    stop)
	i=1
	while [ $i -le $NR_PEERS ]
	do
	    stop_quagga $i
	    i=$(( i+1 ))
	done
	delete_bridge $BRIDGE_NAME
	;;
    *)
	echo $1
	echo "Usage: root-server-docker {start|stop}"
	exit 2
	;;
esac


