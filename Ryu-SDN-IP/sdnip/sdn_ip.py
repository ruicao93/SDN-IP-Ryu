# encoding: utf-8
from netaddr import IPNetwork
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import ether_types
from ryu.topology import api as topo_api
from ryu.services.protocols.bgp.bgpspeaker import BGPSpeaker
from ryu.lib.ofp_pktinfilter import packet_in_filter, RequiredTypeFilter
from conf_mgr import SDNIPConfigManager
from fwd_util import FwdUtil
from hop_db import HopDB

"""
        SDN-IP主要类，负责完成下述功能：
        1.在Ryu上启动一个BGPSpeaker作为iBGP Speaker，并与SDN域内的其他BGPSpeaker连接，获取route信息(SDN-IP BGPSpeaker<---->Internal BGPSpeaker);
            对应方法: __init__()
        2.建立SDN域内BGPSpeaker与域外BGPSpeaker的连接(Internal BGPSpeaker<--->External BGPSpeaker);
            对应方法:　bgp_packet_in_handler()
        3.建立访问外部主机的数据路径(Traffic--->External Hosts)
            对应方法:best_path_change_handler()
        5.建立外部主机访问本地主机的路径(External Host---> Local Host)
            对应方法: internet_to_host_route_handler()
        4.建立内部主机间访问的数据路径(Local Host <--->Local Host)
            对应方法: internal_host_route_handler()
"""
class SDNIP(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'fwd': FwdUtil,
        'hop_db': HopDB
    }
    """
        初始化方法
    """
    def __init__(self, *args, **kwargs):
        super(SDNIP, self).__init__(*args, **kwargs)
        self.fwd_util = kwargs['fwd']
        self.hop_db = kwargs['hop_db']
        self.cfg_mgr = SDNIPConfigManager() #获取SDN－IP配置信息
        # 在Ryu上运行一个iBGPSpeaker
        self.bgp_speaker =\
            BGPSpeaker(self.cfg_mgr.as_number,      #AS号
                       str(self.cfg_mgr.router_id),     #iBGP的router id
                       bgp_server_port=self.cfg_mgr.listen_port,        #监听BGP协议的端口号
                       best_path_change_handler=self.best_path_change_handler,      #当路由信息变化时调用此方法
                       peer_down_handler=self.peer_down_handler,        #BGP对等体下线
                       peer_up_handler=self.peer_up_handler)        #BGP对等体上线

        speaker_ids = self.cfg_mgr.get_all_speaker_id()
        # 建立iBGPSpeaker与SDN域内的BGPSpeaker的连接
        for speaker_id in speaker_ids:
            self.bgp_speaker.neighbor_add(speaker_id,
                                          self.cfg_mgr.as_number,
                                          is_next_hop_self=True)
        # 启动一个线程，用于修复访问外部主机的数据路径
        #hub.spawn(self.prefix_check_loop)



    """
        当路由信息变化时，调用此方法，建立访问外部主机的数据路径。
        参数：
            ev: 路由更新时间，含有访问目的网络的下一跳地址信息。
        建立的路径有:
        1.穿过本地的流量到外部主机的路径(Transit Traffic ---> Internet)
        2.本地主机访问外部主机的路径(Local Host ---> Internet)
    """
    def best_path_change_handler(self, ev):
        self.logger.info('best path changed:')
        self.logger.info('remote_as: %d', ev.remote_as)
        self.logger.info('route_dist: %s', ev.route_dist)
        self.logger.info('prefix: %s', ev.prefix)
        self.logger.info('nexthop: %s', ev.nexthop)
        self.logger.info('label: %s', ev.label)
        self.logger.info('is_withdraw: %s', ev.is_withdraw)
        self.logger.info('')

        #　取网络前缀
        prefix_nw = IPNetwork(ev.prefix)
        # 不处理本地网络更新
        for internal_network in self.cfg_mgr.get_internal_networks():
            int_nw = IPNetwork(internal_network)

            if int_nw == prefix_nw:
                self.logger.info('Internal network, ignored.')
                return
        if ev.is_withdraw:
            self.hop_db.remove_hop(ev.prefix)
        else:
            # 记录访问目的网络的下一跳地址信息
            self.hop_db.add_hop(ev.prefix, ev.nexthop)

    """
        建立BGPSpeaker间的连接。
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def bgp_packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        ofproto = dp.ofproto

        pkt = packet.Packet(msg.data)
        tcp_header = pkt.get_protocol(tcp.tcp)

        #只处理BGP数据包，tcp端口为179
        if tcp_header is None or (tcp_header.src_port is not 179 and
                                          tcp_header.dst_port is not 179):
            return

        ipv4_header = pkt.get_protocol(ipv4.ipv4)
        src_ip = ipv4_header.src
        dst_ip = ipv4_header.dst
        self.logger.info("BGP from %s to %s", src_ip, dst_ip)

        # 获取源、目的主机信息
        hosts = topo_api.get_all_host(self)
        src_host = None
        dst_host = None

        for host in hosts:
            if src_ip in host.ipv4:
                src_host = host

            elif dst_ip in host.ipv4:
                dst_host = host
        if src_host is None or dst_host is None:
            return

        #　建立BGPSpeaker间的数据路径
        src_port = src_host.port
        dst_port = dst_host.port
        dst_mac = dst_host.mac
        to_dst_match = dp.ofproto_parser.OFPMatch(eth_dst=dst_mac,
                                                  ipv4_dst=dst_ip,
                                                  eth_type=2048)
        pre_actions = [
            dp.ofproto_parser.OFPActionSetField(eth_dst=dst_mac)
        ]
        port_no = self.fwd_util.setup_shortest_path(src_port.dpid,
                                               dst_port.dpid,
                                               dst_port.port_no,
                                               to_dst_match,pre_actions )
        #　将首个数据包直接递交给目的主机，防止首包丢失
        if port_no is None:
            return
        self.fwd_util.packet_out(dp, msg, port_no)

    """
        处理packet-in请求，建立到外部主机的单向数据路径。
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    @packet_in_filter(RequiredTypeFilter, {'types': [ipv4.ipv4]})
    def internal_host_route_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        ofproto = dp.ofproto

        pkt = packet.Packet(msg.data)
        ipv4_header = pkt.get_protocol(ipv4.ipv4)

        src_ip = ipv4_header.src
        dst_ip = ipv4_header.dst
        #只处理目的不是本地的访问
        if self.cfg_mgr.is_internal_host(dst_ip):
            return
        #　获取下一跳信息，若下一条信息不存在，不处理
        nexthop_info = self.hop_db.get_nexthop_by_ip(dst_ip)
        if not nexthop_info:
            return
        nexthop_prefix = nexthop_info[0]
        nexthop = nexthop_info[1]
        nexthop_host = self.fwd_util.get_host(nexthop)
        if nexthop_host is None:
            return
        #　建立主机间的数据路径
        host_match = \
            dp.ofproto_parser.OFPMatch(ipv4_dst=(str(nexthop_prefix.ip), str(nexthop_prefix.netmask)), eth_type=2048)
        pre_actions = [
            dp.ofproto_parser.OFPActionSetField(eth_dst=nexthop_host.mac)
        ]
        self.logger.info("daowaiwaiwai")
        self.fwd_util.setup_shortest_path(dpid,
                                          nexthop_host.port.dpid,
                                          nexthop_host.port.port_no,
                                     host_match,
                                          pre_actions)
        #　将首个数据包直接递交给目的主机，防止首包丢失
        switch = topo_api.get_switch(self, nexthop_host.port.dpid)[0]
        self.fwd_util.packet_out(switch.dp,msg,nexthop_host.port.port_no)

    """
        处理packet-in请求，建立目的主机为本地主机的单向数据路径。
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    @packet_in_filter(RequiredTypeFilter, {'types': [ipv4.ipv4]})
    def internet_to_host_route_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        ofproto = dp.ofproto

        pkt = packet.Packet(msg.data)
        ipv4_header = pkt.get_protocol(ipv4.ipv4)

        src_ip = ipv4_header.src
        dst_ip = ipv4_header.dst
        # 若目的主机不是本地主机，不处理
        if not self.cfg_mgr.is_internal_host(dst_ip):
            return

        #获取目的主机信息，若目的主机不存在，不处理
        dst_host = self.fwd_util.get_host(dst_ip)
        if dst_host is None:
            return
        #到本地主机的数据路径
        host_match = \
            dp.ofproto_parser.OFPMatch(ipv4_dst=dst_ip, eth_type=2048)
        pre_actions = [
            dp.ofproto_parser.OFPActionSetField(eth_dst=dst_host.mac)
        ]
        self.logger.info("daoneineinei")
        self.fwd_util.setup_shortest_path(dpid,
                                     dst_host.port.dpid,
                                     dst_host.port.port_no,
                                     host_match,
                                     pre_actions)
        # 　将首个数据包直接递交给目的主机，防止首包丢失
        switch = topo_api.get_switch(self, dst_host.port.dpid)[0]
        self.fwd_util.packet_out(switch.dp, msg, dst_host.port.port_no)

    def peer_down_handler(self, remote_ip, remote_as):
        self.logger.info('peer down:')
        self.logger.info('remote_as: %d', remote_as)
        self.logger.info('remote ip: %s', remote_ip)
        self.logger.info('')

    def peer_up_handler(self, remote_ip, remote_as):
        self.logger.info('peer up:')
        self.logger.info('remote_as: %d', remote_as)
        self.logger.info('remote ip: %s', remote_ip)
        self.logger.info('')

    """
        修复访问外部主机的数据路径
    """

    def prefix_check_loop(self):
        while True:
            prefixs_to_install = self.hop_db.get_uninstalled_prefix_list()
            self.logger.debug("prefix to install: %s", str(prefixs_to_install))

            for prefix in prefixs_to_install:
                prefix_nw = IPNetwork(prefix)

                for internal_network in self.cfg_mgr.get_internal_networks():
                    int_nw = IPNetwork(internal_network)

                    if int_nw == prefix_nw:
                        self.logger.info('Internal network, ignored.')
                        continue
                nexthop = self.hop_db.get_nexthop(prefix)
                self.install_best_path(prefix, nexthop)

            hub.sleep(3)

    """
        根据下一跳地址建立到目的网络的路径[Traffic(dst_ip in prefix) ---> nexthot host]
    """

    def install_best_path(self, prefix, nexthop):
        # 获取下一跳路由器信息
        nexthop_host = self.fwd_util.get_host(nexthop)
        self.logger.debug("nexthop host: %s", str(nexthop_host))
        if nexthop_host is None:
            return

        nexthop_port = nexthop_host.port
        nexthop_mac = nexthop_host.mac
        nexthop_dpid = nexthop_port.dpid
        nexthop_port_no = nexthop_port.port_no
        prefix_ip = str(IPNetwork(prefix).ip)
        prefix_mask = str(IPNetwork(prefix).netmask)
        '''
            在通往下一跳主机路径上的每个switch上下发流表：
            匹配：
                数据包类型为IPV4
                目的ipv4网络为prefix
            处理:
                修改目的Mac为下一跳路由器Mac
                将数据包转发往下一跳方向
        '''
        for dp in self.fwd_util.get_all_datapaths():
            from_dpid = dp.id
            nexthop_match = \
                dp.ofproto_parser.OFPMatch(ipv4_dst=(prefix_ip, prefix_mask),
                                           eth_type=2048)
            pre_actions = [
                dp.ofproto_parser.OFPActionSetField(eth_dst=nexthop_mac)
            ]

            self.fwd_util.setup_shortest_path(from_dpid,
                                              nexthop_dpid,
                                              nexthop_port_no,
                                              nexthop_match,
                                              pre_actions)

        self.hop_db.install_prefix(prefix)

#app_manager.require_app('ryu.app.gui_topology.gui_topology')