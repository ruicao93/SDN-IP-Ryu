# encoding: utf-8
import networkx as nx
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import api as topo_api

"""
    提供一些操作流表、建立数据路径的公共方法
"""
class FwdUtil(app_manager.RyuApp):
    '''
    Forward utilization
    '''
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FwdUtil, self).__init__(*args, **kwargs)
        self.dps = {}

    """
        下发table-miss流表项，让交换机对于不会处理的数据包通过packet-in消息上交给Ryu控制器
    """
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    """
        建立数据路径
    """
    def setup_shortest_path(self,
                            from_dpid,
                            to_dpid,
                            to_port_no,
                            to_dst_match,
                            pre_actions=[]):
        nx_grapth = self.get_nx_graph()
        path = self.get_shortest_path(nx_grapth, from_dpid, to_dpid)

        if path is None:
            return
        port_no = 0
        if len(path) == 1:
            dp = self.get_datapath(from_dpid)
            actions = [dp.ofproto_parser.OFPActionOutput(to_port_no)]
            self.add_flow(dp, 1, to_dst_match, pre_actions+actions)
            port_no = to_port_no
        else:
            self.install_path(to_dst_match, path, nx_grapth, pre_actions)
            dst_dp = self.get_datapath(to_dpid)
            actions = [dst_dp.ofproto_parser.OFPActionOutput(to_port_no)]
            self.add_flow(dst_dp, 1, to_dst_match, pre_actions+actions)
            port_no = nx_grapth.edge[path[0]][path[1]]['src_port']

        return port_no

    """
        计算最短路径
    """
    def get_shortest_path(self, nx_graph, src_dpid, dst_dpid):

        if nx.has_path(nx_graph, src_dpid, dst_dpid):
            return nx.shortest_path(nx_graph, src_dpid, dst_dpid)

        return None
    """
        生成全局topo图
    """
    def get_nx_graph(self):
        graph = nx.DiGraph()
        switches = topo_api.get_all_switch(self)
        links = topo_api.get_all_link(self)

        for switch in switches:
            dpid = switch.dp.id
            graph.add_node(dpid)

        for link in links:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no
            graph.add_edge(src_dpid,
                           dst_dpid,
                           src_port=src_port,
                           dst_port=dst_port)
        return graph

    """
        根据最短路径下发流表
    """
    def install_path(self, match, path, nx_graph, pre_actions=[]):
        for index, dpid in enumerate(path[:-1]):
            port_no = nx_graph.edge[path[index]][path[index + 1]]['src_port']
            dp = self.get_datapath(dpid)
            actions = [dp.ofproto_parser.OFPActionOutput(port_no)]
            self.add_flow(dp, 1, match, pre_actions+actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                hard_timeout=0,
                                instructions=inst)
        datapath.send_msg(mod)

    def get_datapath(self, dpid):
        if dpid not in self.dps:
            switch = topo_api.get_switch(self, dpid)[0]
            self.dps[dpid] = switch.dp
            return switch.dp

        return self.dps[dpid]

    def get_all_datapaths(self):
        switches = topo_api.get_all_switch(self)

        for switch in switches:
            dp = switch.dp
            dpid = dp.id
            self.dps[dpid] = dp

        return self.dps.values()

    """
        根据IP获取主机信息
    """

    def get_host(self, ip):
        hosts = topo_api.get_all_host(self)

        for host in hosts:
            if ip in host.ipv4:
                return host

        return None

    """
        将一个数据包直接从某个交换机的某个端口发出
    """
    def packet_out(self, dp, msg, out_port):
        ofproto = dp.ofproto
        actions = [dp.ofproto_parser.OFPActionOutput(out_port)]
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, in_port=msg.match['in_port'],
            buffer_id=ofproto.OFP_NO_BUFFER,
            actions=actions, data=msg.data)
        dp.send_msg(out)