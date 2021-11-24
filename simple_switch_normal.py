from operator import attrgetter

from ryu.base import app_manager

from ryu.controller import ofp_event

from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER

from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet

from ryu.lib.packet import ethernet

from ryu.lib import hub


class DynamicUtilize(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):

        super(DynamicUtilize, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.vlan_config = {'1': [1, 2, 3, 4, 5, 6],
                            '2': [1, 2, 7, 5],
                            '3': [3, 4, 8, 6],
                            '4': [5, 6, 7, 8],
                            '5': [1, 4, 8, 7],
                            '6': [2, 5, 1, 4]}

        self.datapaths = {}

        self.root_table = {'1': [1, 3, 5, 7], '2': [2, 4, 6, 8]}

        self.vlan_cost = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0}

        self.a = {1: 1, 2: 1, 3: 1, 4: 1, 5: 1, 6: 1}

        self.b = {1: 2, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2}

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        # install table-miss flow entry

        # We specify NO BUFFER to max_len of the output action due to OVS bug

        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER)]

        self.add_flow(datapath, 0, 0, match, actions)

    def add_flow(
            self,
            datapath,
            cookie,
            priority,
            match,
            actions,
            buffer_id=None):

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        idle_timeout = 40

        hard_timeout = 40

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions)]

        if buffer_id:

            mod = parser.OFPFlowMod(
                datapath=datapath,
                cookie=cookie,
                buffer_id=buffer_id,
                priority=priority,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                match=match,
                instructions=inst)

        else:

            mod = parser.OFPFlowMod(
                datapath=datapath,
                cookie=cookie,
                priority=priority,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                match=match,
                instructions=inst)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        # If you hit this you might want to increase

        # the "miss_send_length" of your switch

        if ev.msg.msg_len < ev.msg.total_len:

            self.logger.debug(
                "packet truncated: only %s of %s bytes",
                ev.msg.msg_len,
                ev.msg.total_len)

        msg = ev.msg

        datapath = msg.datapath

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # get vlan_id and bound it to a cookie

        vlan_id = self.vlan_id(pkt)

        cookie = vlan_id

        dst = eth.dst

        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.

        self.mac_to_port[dpid][src] = in_port

        # from here on, we divide this function into two parts

        # part 1:normal operation: if the dst_mac is known,install a flow entry
        # and forward it using pkt_out

        # else just flood with pkt_out

        if dpid == 7 or dpid == 8 or in_port in [1, 2]:

            if dst in self.mac_to_port[dpid]:

                out_port = self.mac_to_port[dpid][dst]

            else:

                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time

            if out_port != ofproto.OFPP_FLOOD:

                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)

                # verify if we have a valid buffer_id, if yes avoid to send
                # both

                # flow_mod & packet_out

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:

                    self.add_flow(
                        datapath, cookie, 1, match, actions, msg.buffer_id)

                    return

                else:

                    self.add_flow(datapath, cookie, 1, match, actions)

            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:

                data = msg.data

            # if packet come from port1 or port2 in (access) switches : flood
            # to all port except the other

            if dpid != 7 and dpid != 8 and out_port == ofproto.OFPP_FLOOD:

                actions = []

                # flood to ports from 3 to 9 , that's enough for only 6 hosts
                # or 6 vlans.

                for x in range(3, 10):

                    actions.append(parser.OFPActionOutput(x))

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data)

            datapath.send_msg(out)

        # part 2: install a flow with Vlan-id matching through the cookie
        # (cookie = Vlan-id),then fowrward with a packet out to the root.

        else:

            vlan_id = self.vlan_id(pkt)

            cookie = vlan_id

            if vlan_id in self.root_table['1']:

                output_port = self.a[dpid]

                match = parser.OFPMatch(
                    in_port=in_port,
                    vlan_vid=vlan_id | ofproto_v1_3.OFPVID_PRESENT)

                actions = [parser.OFPActionOutput(output_port)]

                self.add_flow(datapath, cookie, 1, match, actions)

            if vlan_id in self.root_table['2']:

                output_port = self.b[dpid]

                match = parser.OFPMatch(
                    in_port=in_port,
                    vlan_vid=vlan_id | ofproto_v1_3.OFPVID_PRESENT)

                actions = [parser.OFPActionOutput(output_port)]

                self.add_flow(datapath, cookie, 1, match, actions)

            data = None

            if msg.buffer_id == ofproto.OFP_NO_BUFFER:

                data = msg.data

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data)

            datapath.send_msg(out)

    def vlan_id(self, pkt):

        vlan_id = 0

        for p in pkt:

            if p.protocol_name == 'vlan':

                vlan_id = p.vid

        return vlan_id

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:

            if datapath.id not in self.datapaths:

                self.logger.debug("register datapath: %016x", datapath.id)

                self.datapaths[datapath.id] = datapath

            elif ev.state == DEAD_DISPATCHER:

                if datapath.id in self.datapaths:

                    self.logger.debug(
                        "unregister datapath: %016x", datapath.id)

                    del self.datapaths[datapath.id]

    def _monitor(self):

        while True:

            self.vlan_cost = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0}

            hub.sleep(140)

            print 'do the traffic'

            hub.sleep(20)

            print 'stop traffic'

            hub.sleep(10)

            self.send_aggregate_stats_request()

            for dp in self.datapaths.values():

                if dp.id == 7 or dp.id == 8:

                    self._request_stats(dp)

            hub.sleep(5)

            print 'VLAN Costs : ', self.vlan_cost

            self._update_roots()

    def _request_stats(self, datapath):

        self.logger.debug("send stats request: %016x", datapath.id)

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        for i in self.vlan_cost.keys():

            match = parser.OFPMatch()

            cookie = i

            cookie_mask = 0xFFFFFFFFFFFFFFFF

            req = parser.OFPFlowStatsRequest(
                datapath,
                0,
                ofproto.OFPTT_ALL,
                ofproto.OFPP_ANY,
                ofproto.OFPG_ANY,
                cookie,
                cookie_mask,
                match)

            datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):

        body = ev.msg.body

        x = 0

        i = 0

        for stat in ev.msg.body:

            i = i + 1

            x = stat.cookie

        self.update_vlan_cost(x, i)

    def update_vlan_cost(self, v, c):

        if c != 0 and v != 0:

            self.vlan_cost[v] = self.vlan_cost[v] + c

    def _update_roots(self):

        self.mac_to_port = {}

        previous_table = self.root_table

        self.root_table = {'1': [], '2': []}

        cost_table = {'1': [], '2': []}

        deleted_root = []

        x = sorted(
            self.vlan_cost,
            key=self.vlan_cost.__getitem__,
            reverse=True)

        self.root_table['1'].append(x[0])

        cost_table['1'].append(self.vlan_cost[x[0]])

        self.root_table['2'].append(x[1])

        cost_table['2'].append(self.vlan_cost[x[1]])

        for i in range(2, 8, 1):

            if sum(cost_table['1']) > sum(cost_table['2']):

                self.root_table['2'].append(x[i])

                cost_table['2'].append(self.vlan_cost[x[i]])

            else:

                self.root_table['1'].append(x[i])

                cost_table['1'].append(self.vlan_cost[x[i]])

        print 'root_table : ', self.root_table

        for j in self.root_table['1']:

            if j not in previous_table['1']:

                deleted_root.append(j)

        for k in self.root_table['2']:

            if k not in previous_table['2']:

                deleted_root.append(k)

        self.del_root(deleted_root)

    def del_root(self, deleted_root):

        for c in deleted_root:

            for dp in self.datapaths.values():

                if dp.id < 7:

                    ofproto = dp.ofproto

                    parser = dp.ofproto_parser

                    match = parser.OFPMatch()

                    cookie = c

                    cookie_mask = 0xFFFFFFFFFFFFFFFF

                    datapath = dp

                    mod = parser.OFPFlowMod(
                        datapath=datapath,
                        cookie=cookie,
                        cookie_mask=cookie_mask,
                        command=ofproto.OFPFC_DELETE,
                        out_port=ofproto.OFPP_ANY,
                        out_group=ofproto.OFPG_ANY,
                        match=match)

                    datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):

        msg = ev.msg

        dp = msg.datapath

        ofp = dp.ofproto

        desc = msg.desc

        parser = dp.ofproto_parser

        port_no = desc.port_no

        if desc.config == 1 and dp.id < 7 and port_no in [1, 2]:

            if port_no == 1:

                output_port = 2

            if port_no == 2:

                output_port = 1

            for x in self.vlan_config[str(dp.id)]:

                for dp in self.datapaths.values():

                    if dp.id < 7:

                        for i in [3, 4, 5, 6, 7, 8, 9, 10]:

                            cookie = x

                            match = parser.OFPMatch(
                                in_port=i, vlan_vid=x | ofproto_v1_3.OFPVID_PRESENT)

                            actions = [parser.OFPActionOutput(output_port)]

                            self.add_flow(dp, cookie, 5, match, actions)

        if desc.config == 0 and dp.id < 7 and port_no in [1, 2]:

            if port_no == 1:

                output_port = 2

            if port_no == 2:

                output_port = 1

            for x in self.vlan_config[str(dp.id)]:

                for dp in self.datapaths.values():

                    if dp.id < 7:

                        for i in [3, 4, 5, 6, 7, 8, 9, 10]:

                            cookie = x

                            match = parser.OFPMatch(
                                in_port=i, vlan_vid=x | ofproto_v1_3.OFPVID_PRESENT)

                            actions = [parser.OFPActionOutput(output_port)]

                            self.delete_flow(dp, cookie, 5, match, output_port)

    def delete_flow(self, datapath, cookie, priority, match, output_port):

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=output_port,
            out_group=ofproto.OFPG_ANY,
            priority=5,
            match=match)

        datapath.send_msg(mod)

    def send_aggregate_stats_request(self):

        for dp in self.datapaths.values():

            if dp.id == 7 or dp.id == 8:

                ofp = dp.ofproto

                ofp_parser = dp.ofproto_parser

                cookie = cookie_mask = 0

                match = ofp_parser.OFPMatch()

                req = ofp_parser.OFPAggregateStatsRequest(
                    dp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY, cookie, cookie_mask, match)

                dp.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def aggregate_stats_reply_handler(self, ev):

        body = ev.msg.body

        self.logger.debug(
            'AggregateStats: packet_count=%d byte_count=%d '
            'flow_count=%d',
            body.packet_count,
            body.byte_count,
            body.flow_count)
