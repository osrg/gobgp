# Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from fabric.api import local
import re
import os
import time
from constant import *

def test_user_check():
    root = False
    outbuf = local("echo $USER", capture=True)
    user = outbuf
    if user == "root":
        root = True

    return root


def install_docker_and_tools():
    print "start install packages of test environment."
    if test_user_check() is False:
        print "you are not root"
        return

    local("apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "
          "36A1D7869245C8950F966E92D8576A8BA88D21E9", capture=True)
    local('sh -c "echo deb https://get.docker.io/ubuntu docker main > /etc/apt/sources.list.d/docker.list"',
          capture=True)
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
    local("wget https://raw.github.com/jpetazzo/pipework/master/pipework -O /usr/local/bin/pipework",
          capture=True)
    local("chmod 755 /usr/local/bin/pipework", capture=True)
    local("docker pull osrg/quagga", capture=True)
    local("docker pull osrg/gobgp", capture=True)
    local("docker pull osrg/exabgp", capture=True)


def docker_pkg_check():
    docker_exists = False
    outbuf = local("dpkg -l | grep docker | awk '{print $2}'", capture=True)
    dpkg_list = outbuf.split('\n')
    for dpkg in dpkg_list:
        if "lxc-docker" in dpkg:
            docker_exists = True
    return docker_exists


def go_path_check():
    go_path_exist = False
    outbuf = local("echo `which go`", capture=True)
    if "go" in outbuf:
        go_path_exist = True
    return go_path_exist


def docker_container_check():
    container_exists = False
    outbuf = local("docker ps -a", capture=True)
    docker_ps = outbuf.split('\n')
    for container in docker_ps:
        container_name = container.split()[-1]
        if (container_name == GOBGP_CONTAINER_NAME) or \
                (container_name == EXABGP_CONTAINER_NAME) or ("q" in container_name):
            container_exists = True
    return container_exists


def bridge_setting_check():
    setting_exists = False
    for bridge in BRIDGES:
        sysfs_name = "/sys/class/net/" + bridge["BRIDGE_NAME"]
        if os.path.exists(sysfs_name):
            setting_exists = True
            return setting_exists
    return setting_exists


def docker_containers_get():
    containers = []
    cmd = "docker ps -a | awk '{print $NF}'"
    outbuf = local(cmd, capture=True)
    docker_ps = outbuf.split('\n')
    for container in docker_ps:
        if container != "NAMES":
            containers.append(container.split()[-1])
    return containers


def docker_container_set_ipaddress(bridge, name, address):
    cmd = "pipework " + bridge["BRIDGE_NAME"] + " -i e" + bridge["BRIDGE_NAME"]\
          + " " + name + " " + address
    local(cmd, capture=True)


def docker_container_run_quagga(quagga_num, bridge):
    quagga_name = "q" + str(quagga_num)
    cmd = "docker run --privileged=true -v " + CONFIG_DIR + "/" + quagga_name +\
          ":/etc/quagga --name " + quagga_name + " -id osrg/quagga"
    local(cmd, capture=True)
    quagga_address = BASE_NET[bridge["BRIDGE_NAME"]][IP_VERSION] + str(quagga_num) + BASE_MASK[IP_VERSION]
    docker_container_set_ipaddress(bridge, quagga_name, quagga_address)
    # restart the quagga after the docker container has become IP reachable
    cmd = 'docker kill --signal="HUP" ' + quagga_name
    local(cmd, capture=True)


def docker_container_run_gobgp(bridge):
    cmd = "docker run --privileged=true -v " + CONFIG_DIR + ":" + SHARE_VOLUME + " -d --name "\
          + GOBGP_CONTAINER_NAME + " -id osrg/gobgp"
    local(cmd, capture=True)
    docker_container_set_ipaddress(bridge, GOBGP_CONTAINER_NAME, GOBGP_ADDRESS_0[IP_VERSION] + BASE_MASK[IP_VERSION])


def docker_container_run_exabgp(bridge):
    pwd = local("pwd", capture=True)
    test_pattern_dir = pwd + "/exabgp_test_conf"
    cmd = "cp -r " + test_pattern_dir + " " + CONFIG_DIRR
    local(cmd, capture=True)
    cmd = "docker run --privileged=true -v " + CONFIG_DIR + ":" + SHARE_VOLUME + " -d --name "\
          + EXABGP_CONTAINER_NAME + " -id osrg/exabgp"
    local(cmd, capture=True)
    docker_container_set_ipaddress(bridge, EXABGP_CONTAINER_NAME, EXABGP_ADDRESS)


def change_owner_to_root(target):
    cmd = "chown -R root:root " + target
    local(cmd, capture=True)


def create_config_dir():
    cmd = "mkdir " + CONFIG_DIR
    local(cmd, capture=True)

def make_startup_file(log_opt=""):
    file_buff = '#!/bin/bash' + '\n'
    file_buff += "cd /go/src/github.com/osrg/gobgp/gobgpd" + '\n'
    file_buff += "./gobgpd -f " + SHARE_VOLUME + "/gobgpd.conf " + log_opt + " > " + SHARE_VOLUME + "/gobgpd.log 2>&1 "

    cmd = "echo \"" + file_buff + "\" > " + CONFIG_DIR + "/" + STARTUP_FILE_NAME
    local(cmd, capture=True)
    cmd = "chmod 755 " + CONFIG_DIRR + STARTUP_FILE_NAME
    local(cmd, capture=True)


def make_install_file(use_local=False):
    file_buff = '#!/bin/bash' + '\n'

    if use_local:
        file_buff += 'rm -rf  /go/src/github.com/osrg/gobgp' + '\n'
        file_buff += 'cp -r ' + SHARE_VOLUME + '/gobgp /go/src/github.com/osrg/' + '\n'
        file_buff += 'cd /go/src/github.com/osrg/gobgp' + '\n'
    else:
        file_buff += 'cd /go/src/github.com/osrg/gobgp' + '\n'
        file_buff += 'git pull origin master' + '\n'

    file_buff += 'cd gobgp' + '\n'
    file_buff += 'go get -v' + '\n'
    file_buff += 'go build' + '\n'
    file_buff += 'cp gobgp ' + SHARE_VOLUME + '/' + CLI_CMD + '\n'
    file_buff += 'cd ../gobgpd' + '\n'
    file_buff += 'go get -v' + '\n'
    file_buff += 'go build'
    cmd = "echo \"" + file_buff + "\" > " + CONFIG_DIR + "/" + INSTALL_FILE_NAME
    local(cmd, capture=True)
    cmd = "chmod 755 " + CONFIG_DIRR + INSTALL_FILE_NAME
    local(cmd, capture=True)


def docker_container_stop_quagga(quagga):
    cmd = "docker rm -f " + quagga
    local(cmd, capture=True)
    cmd = "rm -rf " + CONFIG_DIRR + quagga
    local(cmd, capture=True)


def docker_container_stop_gobgp():
    cmd = "docker rm -f " + GOBGP_CONTAINER_NAME
    local(cmd, capture=True)


def docker_container_stop_exabgp():
    cmd = "docker rm -f " + EXABGP_CONTAINER_NAME
    local(cmd, capture=True)


def docker_containers_destroy():
    containers = docker_containers_get()
    for container in containers:
        if re.match(r'q[0-9][0-9]*', container) is not None:
            docker_container_stop_quagga(container)
        if container == GOBGP_CONTAINER_NAME:
            docker_container_stop_gobgp()
        if container == EXABGP_CONTAINER_NAME:
            docker_container_stop_exabgp()
    bridge_unsetting_for_docker_connection()
    cmd = "rm -rf " + CONFIG_DIRR
    local(cmd, capture=True)


def docker_container_quagga_append(quagga_num, bridge):
    print "start append docker container."
    docker_container_run_quagga(quagga_num, bridge)


def docker_container_quagga_removed(quagga_num):
    print "start removed docker container."
    quagga = "q" + str(quagga_num)
    docker_container_stop_quagga(quagga)
    print "complete removed docker container."


def bridge_setting_for_docker_connection(bridges):
    # bridge_unsetting_for_docker_connection()
    for bridge in bridges:
        cmd = "brctl addbr " + bridge["BRIDGE_NAME"]
        local(cmd, capture=True)
        if IP_VERSION == IPv6:
            cmd = "ifconfig " + bridge["BRIDGE_NAME"] + " " + IF_CONFIG_OPTION[IP_VERSION] +\
                " add " + bridge[IP_VERSION] + BASE_MASK[IP_VERSION]
        else:
            cmd = "ifconfig " + bridge["BRIDGE_NAME"] + " " + bridge[IP_VERSION]
        local(cmd, capture=True)
        cmd = "ifconfig " + bridge["BRIDGE_NAME"] + " up"
        local(cmd, capture=True)


def bridge_unsetting_for_docker_connection():
    for bridge in BRIDGES:
        sysfs_name = "/sys/class/net/" + bridge["BRIDGE_NAME"]
        if os.path.exists(sysfs_name):
            cmd = "ifconfig " + bridge["BRIDGE_NAME"] + " down"
            local(cmd, capture=True)
            cmd = "brctl delbr " + bridge["BRIDGE_NAME"]
            local(cmd, capture=True)


def start_gobgp():
    cmd = "docker exec gobgp " + INSTALL_FILE
    local(cmd, capture=True)
    cmd = "docker exec -d gobgp " + STARTUP_FILE
    local(cmd, capture=True)


def start_exabgp(conf_file):
    cmd = "docker exec exabgp cp -f " + SHARE_VOLUME + "/exabgp_test_conf/exabgp.env /root/exabgp/etc/exabgp/exabgp.env"
    local(cmd, capture=True)
    conf_path = EXABGP_CONFDIR + "/" + conf_file
    cmd = "docker exec exabgp /root/exabgp/sbin/exabgp " + conf_path + " > /dev/null 2>&1 &"
    local(cmd, capture=True)


def get_notification_from_exabgp_log():
    log_path = CONFIG_DIRR + EXABGP_LOG_FILE
    cmd = "grep notification " + log_path + " | head -1"
    err_mgs = local(cmd, capture=True)
    return err_mgs


def make_config(quagga_num, go_path, bridge, peer_opts="", policy_pattern=""):
    if go_path != "":
        print "specified go path is [ " + go_path + " ]."
        if os.path.isdir(go_path):
            go_path += "/"
        else:
            print "specified go path do not use."
    pwd = local("pwd", capture=True)

    pp = ''
    if policy_pattern:
        pp = " -p " + policy_pattern

    cmd = go_path + "go run " + pwd + "/quagga-rsconfig.go -n " + str(quagga_num) +\
          " -c /tmp/gobgp -v " + IP_VERSION + pp +" -i " + bridge["BRIDGE_NAME"][-1] + " " + peer_opts
    local(cmd, capture=True)


def make_config_with_policy(quagga_num, go_path, bridge, peer_opts="", policy_pattern=""):
    if go_path != "":
        print "specified go path is [ " + go_path + " ]."
        if os.path.isdir(go_path):
            go_path += "/"
        else:
            print "specified go path is not used."
    pwd = local("pwd", capture=True)
    cmd = go_path + "go run " + pwd + "/quagga-rsconfig.go "+" -p "+ policy_pattern + " -n " + str(quagga_num) + \
          " -c /tmp/gobgp -v " + IP_VERSION + " -i " + bridge["BRIDGE_NAME"][-1] + " " + peer_opts
    local(cmd, capture=True)


def update_policy_config(go_path, policy_pattern=""):
    if go_path != "":
        print "specified go path is [ " + go_path + " ]."
        if os.path.isdir(go_path):
            go_path += "/"
        else:
            print "specified go path is not used."

    pwd = local("pwd", capture=True)
    cmd = go_path + "go run " + pwd + "/quagga-rsconfig.go --update-policy "+" -p "+ policy_pattern + \
          " -c /tmp/gobgp "
    local(cmd, capture=True)
    reload_config()


def make_config_append(quagga_num, go_path, bridge, peer_opts="", policy_pattern=""):
    if go_path != "":
        print "specified go path is [ " + go_path + " ]."
        if os.path.isdir(go_path):
            go_path += "/"
        else:
            print "specified go path do not use."
    pwd = local("pwd", capture=True)

    pp = ''
    if policy_pattern:
        pp = " -p " + policy_pattern

    cmd = go_path + "go run " + pwd + "/quagga-rsconfig.go -a " + str(quagga_num) +\
          " -c /tmp/gobgp -v " + IP_VERSION + pp +" -i " + bridge["BRIDGE_NAME"][-1] + " " + peer_opts
    local(cmd, capture=True)


def change_exabgp_version():
    cmd = "docker exec exabgp git -C /root/exabgp pull origin master"
    local(cmd, capture=True)


def reload_config():
    cmd = "docker exec gobgp /usr/bin/pkill gobgpd -SIGHUP"
    local(cmd, capture=True)
    print "gobgp config reloaded."


def init_test_env_executor(quagga_num, use_local, go_path, log_debug=False, is_route_server=True):
    print "start initialization of test environment."

    if docker_container_check() or bridge_setting_check():
        print "gobgp test environment already exists."
        print "so that remake gobgp test environment."
        docker_containers_destroy()

    print "make gobgp test environment."
    create_config_dir()
    bridge_setting_for_docker_connection(BRIDGES)
    make_config(quagga_num, go_path, BRIDGE_0, ("" if is_route_server else "--normal-bgp"))

    # run gobgp docker container
    docker_container_run_gobgp(BRIDGE_0)

    # set log option
    opt = "-l debug" if log_debug else ""

    # execute local gobgp program in the docker container if the input option is local
    make_startup_file(log_opt=opt)
    if use_local:
        print "execute gobgp program in local machine."
        pwd = local("pwd", capture=True)
        if A_PART_OF_CURRENT_DIR in pwd:
            gobgp_path = re.sub(A_PART_OF_CURRENT_DIR, "", pwd)
            cmd = "cp -r " + gobgp_path + " " + CONFIG_DIRR
            local(cmd, capture=True)
            make_install_file(use_local=True)
        else:
            print "scenario_test directory is not."
            print "execute gobgp program of osrg/master in github."
            make_install_file()
    else:
        print "execute gobgp program of osrg/master in github."
        make_install_file()

    change_owner_to_root(CONFIG_DIR)
    start_gobgp()

    # run quagga docker container
    for num in range(1, quagga_num + 1):
        docker_container_run_quagga(num, BRIDGE_0)

    print "complete initialization of test environment."


def init_policy_test_env_executor(quagga_num, use_local, go_path, log_debug=False, policy="",
                                  use_ipv6=False, use_exabgp=False):
    print "start initialization of test environment."

    if docker_container_check() or bridge_setting_check():
        print "gobgp test environment already exists."
        print "so that remake gobgp test environment."
        docker_containers_destroy()

    print "make gobgp policy test environment."
    create_config_dir()

    if use_ipv6:
        global IP_VERSION
        IP_VERSION = IPv6
    else:
        global IP_VERSION
        IP_VERSION = IPv4

    bridge_setting_for_docker_connection(BRIDGES)
    make_config(quagga_num, go_path, BRIDGE_0, policy_pattern=policy)

    # run gobgp docker container
    docker_container_run_gobgp(BRIDGE_0)

    if use_exabgp:
        # run exabgp
        make_config_append(100, go_path, BRIDGE_0, peer_opts="--none-peer", policy_pattern=policy)
        docker_container_run_exabgp(BRIDGE_0)
        cmd = "docker exec exabgp cp -rf " + SHARE_VOLUME + "/exabgp /root/"
        local(cmd, capture=True)

    # set log option
    opt = "-l debug" if log_debug else ""

    # execute local gobgp program in the docker container if the input option is local
    make_startup_file(log_opt=opt)
    if use_local:
        print "execute gobgp program in local machine."
        pwd = local("pwd", capture=True)
        if A_PART_OF_CURRENT_DIR in pwd:
            gobgp_path = re.sub(A_PART_OF_CURRENT_DIR, "", pwd)
            cmd = "cp -r " + gobgp_path + " " + CONFIG_DIRR
            local(cmd, capture=True)
            make_install_file(use_local=True)
        else:
            print "local gobgp dosen't exist."
            print "get the latest master gobgp from github."
            make_install_file()
    else:
        print "execute gobgp program of osrg/master in github."
        make_install_file()

    change_owner_to_root(CONFIG_DIR)
    start_gobgp()

    # run quagga docker container
    for num in range(1, quagga_num + 1):
        docker_container_run_quagga(num, BRIDGE_0)

    # start exabgp
    if use_exabgp:
        start_exabgp(EXABGP_COMMON_CONF)

    print "complete initialization of test environment."


def init_ipv6_test_env_executor(quagga_num, use_local, go_path, log_debug=False):
    print "start initialization of test environment."

    if docker_container_check() or bridge_setting_check():
        print "gobgp test environment already exists."
        print "so that remake gobgp test environment."
        docker_containers_destroy()

    print "make gobgp test environment."
    create_config_dir()
    bridge_setting_for_docker_connection([BRIDGE_0])
    make_config(quagga_num, go_path, BRIDGE_0)

    # run gobgp docker container
    docker_container_run_gobgp(BRIDGE_0)

    # set log option
    opt = "-l debug" if log_debug else ""

    # execute local gobgp program in the docker container if the input option is local
    make_startup_file(log_opt=opt)
    if use_local:
        print "execute gobgp program in local machine."
        pwd = local("pwd", capture=True)
        if A_PART_OF_CURRENT_DIR in pwd:
            gobgp_path = re.sub(A_PART_OF_CURRENT_DIR, "", pwd)
            cmd = "cp -r " + gobgp_path + " " + CONFIG_DIRR
            local(cmd, capture=True)
            make_install_file(use_local=True)
        else:
            print "scenario_test directory is not."
            print "execute gobgp program of osrg/master in github."
            make_install_file()
    else:
        print "execute gobgp program of osrg/master in github."
        make_install_file()

    change_owner_to_root(CONFIG_DIR)
    start_gobgp()

    # run quagga docker container
    for num in range(1, quagga_num + 1):
        docker_container_run_quagga(num, BRIDGE_0)

    print "complete initialization of test environment."


def init_malformed_test_env_executor(conf_file, use_local,  go_path, exabgp_path, log_debug=False):
    print "start initialization of exabgp test environment."

    if docker_container_check() or bridge_setting_check():
        print "gobgp test environment already exists."
        print "so that remake gobgp test environment."
        docker_containers_destroy()

    print "make gobgp test environment."
    peer_opts = "--none-peer"
    create_config_dir()
    bridge_setting_for_docker_connection(BRIDGES)
    make_config(1, go_path, BRIDGE_0)
    make_config_append(100, go_path, BRIDGE_0, peer_opts)

    # run gobgp docker container
    docker_container_run_gobgp(BRIDGE_0)
    # run exabgp docker container
    docker_container_run_exabgp(BRIDGE_0)

    # set log option
    opt = "-l debug" if log_debug else ""

    make_startup_file(log_opt=opt)
    # execute local gobgp program in the docker container if the input option is local
    if use_local:
        print "execute gobgp program in local machine."
        pwd = local("pwd", capture=True)
        if A_PART_OF_CURRENT_DIR in pwd:
            gobgp_path = re.sub(A_PART_OF_CURRENT_DIR, "", pwd)
            cmd = "cp -r " + gobgp_path + " " + CONFIG_DIRR
            local(cmd, capture=True)
            make_install_file(use_local=True)
        else:
            print "scenario_test directory is not."
            print "execute gobgp program of osrg/master in github."
            make_install_file()
    else:
        print "execute gobgp program of osrg/master in github."
        make_install_file()

    change_owner_to_root(CONFIG_DIR)

    if exabgp_path != "":
        cmd = "cp -rf %s %s" % (exabgp_path, CONFIG_DIR)
        local(cmd, capture=True)
        cmd = "docker exec exabgp cp -rf " + SHARE_VOLUME + "/exabgp /root/"
        local(cmd, capture=True)
    else:
        change_exabgp_version()

    start_gobgp()

    # run quagga docker container
    docker_container_run_quagga(1, BRIDGE_0)
    start_exabgp(conf_file)


def docker_container_quagga_append_executor(quagga_num, go_path, is_route_server=True):
    make_config_append(quagga_num, go_path, BRIDGE_0, ("" if is_route_server else "--normal-bgp"))
    docker_container_quagga_append(quagga_num, BRIDGE_0)
    reload_config()


def docker_container_ipv6_quagga_append_executor(quagga_nums, go_path):
    print "append ipv6 quagga container."
    global IP_VERSION
    IP_VERSION = IPv6
    bridge_setting_for_docker_connection([BRIDGE_1])
    docker_container_set_ipaddress(BRIDGE_1, GOBGP_CONTAINER_NAME, GOBGP_ADDRESS_1[IP_VERSION] + BASE_MASK[IP_VERSION])
    for quagga_num in quagga_nums:
        make_config_append(quagga_num, go_path, BRIDGE_1)
        docker_container_quagga_append(quagga_num, BRIDGE_1)
    reload_config()


def docker_container_quagga_removed_executor(quagga_num):
    docker_container_quagga_removed(quagga_num)


def docker_container_make_bestpath_env_executor(append_quagga_num, go_path, is_route_server=True):
    print "start make bestpath environment"
    make_config_append(append_quagga_num, go_path, BRIDGE_1, ("" if is_route_server else "--normal-bgp"))
    append_quagga_name = "q" + str(append_quagga_num)
    docker_container_quagga_append(append_quagga_num, BRIDGE_1)
    reload_config()
    docker_container_set_ipaddress(BRIDGE_1, "q2", "11.0.0.2/16")
    docker_container_set_ipaddress(BRIDGE_2, append_quagga_name, "12.0.0.20/16")
    docker_container_set_ipaddress(BRIDGE_2, "q3", "12.0.0.3/16")

