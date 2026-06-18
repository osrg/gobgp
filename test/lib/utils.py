import time


def _get_link_local_address(ctn, ifname):
    out = ctn.local(
        'ip -6 -o addr show dev {0} scope link'.format(ifname),
        capture=True,
    )
    for line in out.split('\n'):
        if ' fe80:' not in line:
            continue
        return line.split()[3].split('/')[0]
    raise Exception('link local address not found')

def _ensure_neighbor_reachable(ctn, ifname, target_lladdr):
    out = ctn.local('ip -6 n show dev {0}'.format(ifname), capture=True)
    lines = [line for line in out.split('\n') if line.startswith('fe80')]
    for line in lines:
        lladdr = line.split()[0]
        if lladdr == target_lladdr:
            return 'REACHABLE' in line
    return False


# probe_link_local_address discovers the IPv6 link local address of the
# interfaces for container a and b connected p2p (or bridge network that only a
# and b exists).
def probe_link_local_address(a, b, aif, bif):
    done = False

    a_lladdr = _get_link_local_address(a, aif)
    b_lladdr = _get_link_local_address(b, bif)

    for i in range(20):
        a.local('ping6 -c 1 {0}%{1}'.format(b_lladdr, aif))
        b.local('ping6 -c 1 {0}%{1}'.format(a_lladdr, bif))
        if _ensure_neighbor_reachable(a, aif, b_lladdr) and _ensure_neighbor_reachable(b, bif, a_lladdr):
            done = True
            break
        time.sleep(1)

    if not done:
        raise Exception('timeout')
