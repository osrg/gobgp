class Peer:
    def __init__(self, peer_ip, peer_id, peer_as, ip_version):
    # def __init__(self, peer_ip, peer_id, peer_as):
        self.peer_ip = peer_ip
        self.peer_id = peer_id
        self.peer_as = peer_as
        self.ip_version = ip_version
        self.neighbors = []
        self.destinations = {}


class Destination:
    def __init__(self, prefix):
        self.prefix = prefix
        self.paths = []


class Path:
    def __init__(self, network, nexthop):
        self.network = network
        self.nexthop = nexthop
        self.origin = None
        self.as_path = []
        self.metric = None