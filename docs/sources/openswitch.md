# Coordination with OpenSwitch

GoBGP will be able to coordination with [OpenSwitch](http://www.openswitch.net)
by connecting to ovsdb using unixsocket(use [ovsdb library of golang](https://github.com/osrg/libovsdb)).
And GoBGP will behaves as BGP agent of OpenSwitch because GoBGP can share configuration
and routing information in coordination with OpenSwitch.

This page explains how to coordination to OpenSwitch.
And this example have step that share configuration and routing information between OpenSwitch and Gobgp in [docker container](https://hub.docker.com/r/openswitch/genericx86-64/).


## Prerequisites

- Install the docker environment referring to the [here](https://docs.docker.com/engine/installation/ubuntulinux/)
- Install the gobgp refarring to the [here](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md)

## Getting and Running OpenSwitch container
- Getting image

 Thera are two ways, to get OpenSwitch docker image.
 First way, get image from DockerHub using the **docker pull** command.
 Second way, build the iamge refarring to the [Step-by-Step Guide](http://www.openswitch.net/documents/dev/step-by-step-guide) of OpenSwitch.

 - In the case of **docker pull**
  ```bash
  $ sudo docker pull openswitch/genericx86-64
  $ sudo docker images
  REPOSITORY                 TAG                 IMAGE ID            CREATED             SIZE
  openswitch/genericx86-64   latest              69682b4baeba        4 months ago        321.3 MB        1.278 GB
  ```

- Running container

 Share the GoBGP binary when you execute docker run command.
 ```bash
 sudo docker run --privileged -v /tmp:/tmp -v /dev/log:/dev/log -v /sys/fs/cgroup:/sys/fs/cgroup -v $GOPATH/bin:/home/root/bin -h ops --name ops openswitch/genericx86-64 /sbin/init &
 $ sudo docker ps -a
 CONTAINER ID        IMAGE                      COMMAND             CREATED             STATUS              PORTS               NAMES
 4eebc0f25f9c        openswitch/genericx86-64   "/sbin/init"        3 seconds ago       Up 3 seconds                            ops
 ```

## Starting Coordination with OpenSwitch
- Enter the OpenSwitch container
 ```bash
 % sudo docker exec -it ops bash
 ```
 
- Setting OpenSwitch
 ```bash
 bash-4.3# vtysh
 switch# show running-config
 Current configuration:
 !
 !
 !
 switch# configure terminal
 switch(config)# router bgp 65001
 switch(config-router)# bgp router-id 10.0.255.1
 switch(config-router)# neighbor 10.0.255.2 remote-as 65002
 switch(config-router)# do show running-config
 Current configuration:
 !
 !
 !
 router bgp 65001
     bgp router-id 10.0.255.1
     neighbor 10.0.255.2 remote-as 65002
 !
 ```

- Starting GoBGP
 ```bash
 bash-4.3# cd /home/root/bin
 bash-4.3# gobgpd --openswitch -p
 INFO[0000] gobgpd started
 INFO[0000] Coordination with OpenSwitch
 INFO[0000] Peer 10.0.255.2 is added
 INFO[0015] Peer Up
 ```

 If GoBGP has routes in Global Rib, routes relayed to the OpenSwitch as follows:
 ```bash
 bash-4.3# vtysh
 switch# show ip bgp
 Status codes: s suppressed, d damped, h history, * valid, > best, = multipath,
               i internal, S Stale, R Removed
 Origin codes: i - IGP, e - EGP, ? - incomplete

 Local router-id 10.0.255.1
    Network          Next Hop            Metric LocPrf Weight Path
 *  10.10.10.0/24    10.0.255.2            0      0  32768 65002 i
 *  10.10.11.0/24    10.0.255.2            0      0  32768 65002 i
 *  10.10.12.0/24    10.0.255.2            0      0  32768 65002 i
 Total number of entries 3
 ```

