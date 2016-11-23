# encoding: utf-8
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.ofp_pktinfilter import packet_in_filter, RequiredTypeFilter
from ryu.topology import api as topo_api
from conf_mgr import SDNIPConfigManager
from fwd_util import FwdUtil
from hop_db import HopDB
"""
    代理回复Arp请求。
"""
class ArpProxy(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        'fwd': FwdUtil,
        'hop_db': HopDB
    }

    def __init__(self, *args, **kwargs):
        super(ArpProxy, self).__init__(*args, **kwargs)
        self.fwd_util = kwargs['fwd']
        self.hop_db = kwargs['hop_db']
        self.cfg_mgr = SDNIPConfigManager()

    """
        代理回复Arp请求,有以下几种情况：
        1.目的主机为本地网络主机：
            查找主机,若找到则回复其Mac地址；
            若找不到，则将此Arp请求洪泛出去。
        2.目的主机为BGPSpeaker(包括local和external)：
            查找主机Mac并回复。
        3.目的主机为外部网络主机：
            将本地第一个BGPSpeaker作为默认网关，回复它的Mac。
    """
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    @packet_in_filter(RequiredTypeFilter, {'types': [arp.arp]})
    def arp_packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        arp_header = pkt.get_protocol(arp.arp)
        src_ip = arp_header.src_ip
        src_mac = arp_header.src_mac
        dst_ip = arp_header.dst_ip
        dst_mac = None
        '''
            1.目的主机为本地网络主机：
                查找主机,若找到则回复其Mac地址；
                若找不到，则将此Arp请求洪泛出去。
            2.目的主机为BGPSpeaker(包括local和external)：
                查找主机Mac并回复。
        '''
        dst_host = self.fwd_util.get_host(dst_ip)
        if dst_host is not None:
            dst_mac = dst_host.mac
        else:
            if self.cfg_mgr.is_internal_host(dst_ip):
                self.flood(msg)
                return
            else:#如果不是本地主机，则找下一跳路由器
                nexthop_info = self.hop_db.get_nexthop_by_ip(dst_ip)
                if not nexthop_info:
                    return
                nexthop_prefix = nexthop_info[0]
                nexthop = nexthop_info[1]
                nexthop_host = self.fwd_util.get_host(nexthop)
                if nexthop_host is None:
                    return
                dst_mac = nexthop_host.mac
        if arp_header.opcode != arp.ARP_REQUEST:
            return
        if not dst_mac:
            return
        self.logger.info('find mac for %s :%s:', dst_ip,dst_mac )
        # 根据找到的dst_mac构造Arp响应并回复
        actions = [parser.OFPActionOutput(in_port)]
        arp_reply = packet.Packet()
        arp_reply.add_protocol(
            ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                src=dst_mac,
                dst=src_mac
            )
        )
        arp_reply.add_protocol(
            arp.arp(
                opcode=arp.ARP_REPLY,
                src_ip=dst_ip,
                src_mac=dst_mac,
                dst_ip=src_ip,
                dst_mac=src_mac
            )
        )
        arp_reply.serialize()
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions, data=arp_reply.data)
        datapath.send_msg(out)

    """
        洪泛数据包，加入了防网络风暴处理。
    """
    def flood(self, msg):
        switches = topo_api.get_all_switch(self)
        links = topo_api.get_all_link(self)
        link_point_set = set()
        for link in links:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            link_point_set.add((src_dpid,src_port))
            link_point_set.add((dst_dpid, dst_port))
        for switch in switches:
            dp = switch.dp
            for port in switch.ports:
                if (port.dpid, port.port_no) in link_point_set:
                    continue
                self.fwd_util.packet_out(dp, msg, port.port_no)
        return

