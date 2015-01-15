from fabric.api import local
import time
import os

GOBGP_CONTAINER_NAME = "gobgp"
GOBGP_ADDRESS = "10.0.255.1/16"
GOBGP_CONFIG_FILE = "gobgpd.conf"
BRIDGE_ADDRESS = "10.0.255.2"
CONFIG_DIR = "/usr/local/gobgp"
CONFIG_DIRR = "/usr/local/gobgp/"
STARTUP_FILE_NAME = "gobgp_startup.sh"
STARTUP_FILE = "/mnt/" + STARTUP_FILE_NAME
BRIDGE_0 = "br0"
BRIDGE_1 = "br1"
BRIDGE_2 = "br2"

sleep_time = 40

def test_user_check():
    root = False
    outbuf = local("echo $USER", capture=True)
    user = outbuf
    if user == "root":
        root = True

    return root


def docker_related_installation():
    local("apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 36A1D7869245C8950F966E92D8576A8BA88D21E9", capture=True)
    local('sh -c "echo deb https://get.docker.io/ubuntu docker main > /etc/apt/sources.list.d/docker.list"', capture=True)
    local("apt-get update", capture=True)
    local("apt-get install -y --force-yes lxc-docker-1.3.2", capture=True)
    local("ln -sf /usr/bin/docker.io /usr/local/bin/docker", capture=True)
    local("gpasswd -a `whoami` docker", capture=True)
    local("apt-get install -y --force-yes emacs23-nox", capture=True)
    local("apt-get install -y --force-yes wireshark", capture=True)
    local("apt-get install -y --force-yes iputils-arping", capture=True)
    local("apt-get install -y --force-yes bridge-utils", capture=True)
    local("apt-get install -y --force-yes tcpdump", capture=True)
    local("apt-get install -y --force-yes lv", capture=True)
    local("wget https://raw.github.com/jpetazzo/pipework/master/pipework -O /usr/local/bin/pipework", capture=True)
    local("chmod 755 /usr/local/bin/pipework", capture=True)
    local("docker pull osrg/quagga", capture=True)
    local("docker pull osrg/gobgp", capture=True)
    local("mkdir /usr/local/gobgp", capture=True)
    local("docker run --privileged=true -v /usr/local/gobgp:/mnt --name gobgp --rm osrg/gobgp go run /root/gobgp/tools/route-server/quagga-rsconfig.go -c /mnt", capture=True)


def docker_pkg_check():
    docker_exists = False
    outbuf = local("dpkg -l | grep docker | awk '{print $2}'", capture=True)
    dpkg_list = outbuf.split('\n')
    for dpkg in dpkg_list:
        # print "lxc-docker in ",dpkg
        if ("lxc-docker" in dpkg):
            docker_exists = True
    return docker_exists


def docker_container_check():
    container_exists = False
    outbuf = local("docker ps", capture=True)
    docker_ps = outbuf.split('\n')
    for container in docker_ps:
        container_name = container.split()[-1]
        if container_name == GOBGP_CONTAINER_NAME:
            container_exists = True
    return container_exists


def get_docker_containers():
    containers = []
    cmd = "docker ps | awk '{print $NF}' | grep -e '^[q][0-9][0-9]*$'"
    outbuf = local(cmd, capture=True)
    docker_ps = outbuf.split('\n')
    for container in docker_ps:
        if container != "NAMES":
            containers.append(container.split()[-1])
    return containers


def docker_run_quagga(quagga_num):
    quagga_name = "q" + str(quagga_num)
    cmd = "docker run --privileged=true -v " + CONFIG_DIR + "/" + quagga_name + ":/etc/quagga --name " + quagga_name + " -id osrg/quagga"
    local(cmd, capture=True)
    quagga_address = "10.0.0." + str(quagga_num) + "/16"
    cmd = "pipework " + BRIDGE_0 + " " + quagga_name + " " + quagga_address
    local(cmd, capture=True)


def docker_run_gobgp():
    cmd = "docker run --privileged=true -v " + CONFIG_DIR + ":/mnt -d --name " + GOBGP_CONTAINER_NAME + " -id osrg/gobgp"
    local(cmd, capture=True)
    cmd = "pipework " + BRIDGE_0 + " " + GOBGP_CONTAINER_NAME + " " + GOBGP_ADDRESS
    local(cmd, capture=True)


def make_startup_file():
    file_buff = '#!/bin/bash' + '\n'
    file_buff += 'cd /root/gobgp' + '\n'
    file_buff += 'git pull origin master' + '\n'
    file_buff += 'go get -v' + '\n'
    file_buff += 'go build' + '\n'
    file_buff += './gobgp -f /mnt/gobgpd.conf'
    cmd = "echo \"" + file_buff + "\" > " + CONFIG_DIRR + STARTUP_FILE_NAME
    local(cmd, capture=True)
    cmd = "chmod 755 " + CONFIG_DIRR + STARTUP_FILE_NAME
    local(cmd, capture=True)


def docker_containers_create(quagga_num):
    bridge_setting_for_docker_connection(BRIDGE_0)
    pwd = local("pwd", capture=True)
    cmd = "go run " + pwd + "/quagga-rsconfig.go -n " + str(quagga_num) + " -c /usr/local/gobgp"
    local(cmd, capture=True)
    for num in range(1, quagga_num + 1):
        docker_run_quagga(num)
    docker_run_gobgp()
    make_startup_file()


def docker_stop_quagga(quagga):
    cmd = "docker rm -f " + quagga
    local(cmd, capture=True)
    cmd = "rm -rf " + CONFIG_DIRR + quagga
    local(cmd, capture=True)


def docker_stop_gobgp():
    cmd = "docker rm -f " + GOBGP_CONTAINER_NAME
    local(cmd, capture=True)


def docker_containers_destroy():
    if docker_container_check() is True:
        containers = get_docker_containers()
        for container in containers:
            docker_stop_quagga(container)
        docker_stop_gobgp()
        bridge_unsetting_for_docker_connection(BRIDGE_0)
        cmd = "rm -rf " + CONFIG_DIRR + GOBGP_CONFIG_FILE
        local(cmd, capture=True)
        cmd = "rm -rf " + CONFIG_DIRR + STARTUP_FILE_NAME
        local(cmd, capture=True)
    else:
        print "docker containers not exists."
        os.exit(1)


def docker_containers_recreate(quagga_num):
    docker_containers_destroy()
    docker_containers_create(quagga_num)


def docker_container_append(quagga_num):
    print "start append docker container."
    pwd = local("pwd", capture=True)
    cmd = "go run " + pwd + "/quagga-rsconfig.go -a " + str(quagga_num) + " -c /usr/local/gobgp"
    local(cmd, capture=True)
    docker_run_quagga(quagga_num)
    cmd = "docker exec gobgp /usr/bin/pkill gobgp -SIGHUP"
    local(cmd, capture=True)
    print "please wait"
    time.sleep(sleep_time)
    print "complete append docker container."


def docker_container_removed(quagga_num):
    print "start remove docker container."
    quagga = "q" + str(quagga_num)
    docker_stop_quagga(quagga)
    print "please wait"
    time.sleep(sleep_time)
    print "complete remove docker container."


def bridge_setting_for_docker_connection(bridge):
    sysfs_name = "/sys/class/net/" + bridge
    if os.path.exists(sysfs_name):
        bridge_unsetting_for_docker_connection(bridge)
        bridge_setting_for_docker_connection(bridge)
    else:
        cmd = "brctl addbr " + bridge
        local(cmd, capture=True)
        cmd = "ifconfig " + bridge + " " + BRIDGE_ADDRESS
        local(cmd, capture=True)
        cmd = "ifconfig " + bridge + " up"
        local(cmd, capture=True)


def bridge_unsetting_for_docker_connection(bridge):
    sysfs_name = "/sys/class/net/" + bridge
    if os.path.exists(sysfs_name):
        cmd = "ifconfig " + bridge + " down"
        local(cmd, capture=True)
        cmd = "brctl delbr " + bridge
        local(cmd, capture=True)


def gobgp_start():
    cmd = "docker exec gobgp " + STARTUP_FILE + " > /dev/null 2>&1 &"
    # cmd = "docker exec gobgp " + STARTUP_FILE
    local(cmd, capture=True)


def init_test_env_executor(quagga_num):
    print "start initialization of test environment."
    if test_user_check() is False:
        print "you are not root"
        print "please run the test after you login as root"
        return

    if docker_pkg_check():
        if docker_container_check():
            print "gobgp test environment already exists."
            print "so that remake gobgp test environment."
            docker_containers_recreate(quagga_num)
        else:
            print "make gobgp test environment."
            docker_containers_create(quagga_num)
    gobgp_start()

    print "please wait"
    time.sleep(sleep_time)
    print "complete initialization of test environment."


def docker_related_install_executor():
    print "start install of docker related"
    if test_user_check() is False:
        print "you are not root"
        print "please run the test after you login as root"
        return
    docker_related_installation()
