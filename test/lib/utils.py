import subprocess

from lib.base import wait_for


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


def _dump_link_local_probe_diagnostics(a, b, aif, bif):
    # Neighbor cache state is intentionally diagnostic-only: kernels may age or
    # report it differently even when packets are already flowing.
    print('[link-local probe diagnostics]')
    for ctn, ifname in ((a, aif), (b, bif)):
        try:
            addr = ctn.local(
                'ip -6 -o addr show dev {0}'.format(ifname),
                capture=True,
            )
        except subprocess.CalledProcessError:
            addr = '<failed to dump IPv6 addresses>'
        try:
            neigh = ctn.local('ip -6 n show dev {0}'.format(ifname), capture=True)
        except subprocess.CalledProcessError:
            neigh = '<failed to dump IPv6 neighbors>'
        print('[{0} {1} addr]\n{2}'.format(ctn.name, ifname, addr))
        print('[{0} {1} neigh]\n{2}'.format(ctn.name, ifname, neigh))


def _ping_link_local(ctn, ifname, target_lladdr):
    ctn.local(
        'ping6 -c 1 -W 1 {0}%{1}'.format(target_lladdr, ifname),
        timeout=5,
    )


def _link_local_ping_reachable(a, b, aif, bif, a_lladdr, b_lladdr):
    # The test needs bidirectional reachability, not a particular instantaneous
    # neighbor-table state. A successful scoped ping is the observable contract.
    try:
        _ping_link_local(a, aif, b_lladdr)
        _ping_link_local(b, bif, a_lladdr)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    return True


# probe_link_local_address discovers the IPv6 link local address of the
# interfaces for container a and b connected p2p (or bridge network that only a
# and b exists).
def probe_link_local_address(a, b, aif, bif):
    a_lladdr = _get_link_local_address(a, aif)
    b_lladdr = _get_link_local_address(b, bif)

    def _reachable():
        return _link_local_ping_reachable(a, b, aif, bif, a_lladdr, b_lladdr)

    try:
        wait_for(_reachable, timeout=20)
    except Exception:
        _dump_link_local_probe_diagnostics(a, b, aif, bif)
        raise
