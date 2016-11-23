# encoding: utf-8
from ryu.base import app_manager
from netaddr import IPNetwork,IPAddress
"""
    记录路由信息：目的网络--->下一跳地址
"""
class HopDB(app_manager.RyuApp):

    def __init__(self):
        super(HopDB, self).__init__()
        self.hops = {}  # prefix -> hop
        self.installed_prefix = []

    def add_hop(self, prefix, next_hop):
        self.hops.setdefault(prefix, next_hop)

    def remove_hop(self,prefix):
        del self.hops[prefix]

    def get_nexthop(self, prefix):
        return  self.hops.get(prefix)

    def get_nexthop_by_ip(self, ip):
        ip_addr = IPAddress(ip)
        for prefix in self.hops.keys():
            cidr = IPNetwork(prefix)
            if ip_addr in cidr:
                return [cidr,self.hops.get(prefix)]
        return None

    def is_prefix_installed(self, prefix):
        return (prefix in self.installed_prefix)

    def get_uninstalled_prefix_list(self):
        result = [prefix for prefix in
                  self.hops.keys() if (prefix not in self.installed_prefix)]
        return result

    def install_prefix(self, prefix):
        self.installed_prefix.append(prefix)

    def get_all_prefixes(self):
        return self.hops.keys()
