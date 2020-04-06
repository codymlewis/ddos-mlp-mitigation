#!/usr/bin/env python2
# -*- coding: utf-8 -*-

'''
The controller of the network.
'''

import sys
import time

import tensorflow as tf
from tensorflow import keras

import numpy as np
from minisom import MiniSom

import pox.lib.packet as pac
from pox.boot import boot
from pox.core import core
from pox.lib.recoco import Timer

import pox.openflow.libopenflow_01 as of


if __name__ != "__main__":
    import pox.forwarding.l2_learning as l2l
    LOG = core.getLogger()

IPV4_PROTOCOLS = {
    pac.ipv4.ICMP_PROTOCOL: "ICMP",
    pac.ipv4.IGMP_PROTOCOL: "IGMP",
    pac.ipv4.TCP_PROTOCOL: "TCP",
    pac.ipv4.UDP_PROTOCOL: "UDP",
}

IPV6_PROTOCOLS = {
    pac.ipv6.ICMP6_PROTOCOL: "ICMP",
    pac.ipv6.IGMP_PROTOCOL: "IGMP",
    pac.ipv6.TCP_PROTOCOL: "TCP",
    pac.ipv6.UDP_PROTOCOL: "UDP",
}

class Flow:
    def __init__(self, src, dst, comm_prot, packets, amount_bytes):
        self.src = src
        self.dst = dst
        self.comm_prot = comm_prot
        self.packets = packets
        self.bytes = amount_bytes
        self.time_created = time.time()
        self.time_last_used = time.time()

    def __str__(self):
        return "{} -> {}: {}".format(self.src, self.dst, self.comm_prot)

    def is_pair(self, other):
        p = self.src == other.dst
        q = self.dst == other.src
        v = self.comm_prot == other.comm_prot
        return p and q and v

    def __eq__(self, other):
        if isinstance(other, Flow):
            p = self.src == other.src
            q = self.dst == other.dst
            v = self.comm_prot == other.comm_prot
            return p and q and v
        return False

    def update(self, packets, amount_bytes):
        self.time_last_used = time.time()
        self.packets += packets
        self.bytes += amount_bytes

class Controller(object):
    def __init__(self, connection, gen_data, label, detect, interval=5.0, clean_interval=30):
        self.connection = connection
        connection.addListeners(self)
        self.label = label
        self.mac_to_port = {}
        self.flows = dict()
        self.growing_flows = dict()
        self.ports = set()
        self.growing_ports = set()
        self.time_started = time.time()
        self.interval = interval
        if gen_data:
            self.data_timer = Timer(interval, self.write_data, recurring=True)
        self.growth_timer = Timer(interval, self.detect_growth, recurring=True)
        self.clean_interval = clean_interval
        self.clean_timer = Timer(clean_interval, self.clean_flows, recurring=True)
        self.detect = detect
        if detect:
            self.model = keras.models.load_model('model.h5')

    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def act_like_switch(self, packet, packet_in):
        if self.detect:
            prediction = np.round(self.model.predict([self.calc_tuple()])[0][0])
            LOG.debug("Prediction: %s", prediction)
            if prediction == 1.0:
                LOG.debug("Attack detected!")
                return
        pl = packet.payload
        if isinstance(pl, pac.arp):
            src = pl.protosrc
            dst = pl.protodst
            comm_prot = "ARP"
        else:
            src = pl.srcip
            dst = pl.dstip
            if isinstance(pl, pac.ipv4):
                comm_prot = IPV4_PROTOCOLS[pl.protocol]
            else:
                comm_prot = "IPV6"
        flow = Flow(src, dst, comm_prot, 1, len(pl))
        flow_name = str(flow)
        if self.flows.get(flow_name):
            self.flows[flow_name].update(1, len(pl))
        else:
            self.flows[flow_name] = flow
        self.growing_flows[flow_name] = flow
        if len(packet_in.data) == packet_in.total_len:
            self.mac_to_port[packet.src] = packet_in.in_port
            self.ports = self.ports.union([packet_in.in_port])
            self.growing_ports = self.growing_ports.union([packet_in.in_port])
            if self.mac_to_port.get(packet.dst):
                self.resend_packet(packet_in, self.mac_to_port[packet.dst])
            else:
                self.resend_packet(packet_in, of.OFPP_ALL)

    def calc_tuple(self):
        interval = time.time() - self.time_started
        amount_packets = []
        amount_bytes = []
        durations = []
        current_time = time.time()
        num_pair_flows = float(0)
        all_flows = self.flows.values()
        num_flows = float(len(all_flows))
        for i, flow in enumerate(all_flows):
            amount_packets.append(flow.packets)
            amount_bytes.append(flow.bytes)
            durations.append(current_time - flow.time_created)
            for other_flow in all_flows[i + 1:]:
                if flow.is_pair(other_flow):
                    num_pair_flows += 1
        all_growing_flows = self.growing_flows.values()
        num_growing_flows = len(all_growing_flows)
        num_growing_pair_flows = 0
        for i, flow in enumerate(all_growing_flows):
            for other_flow in all_growing_flows[i + 1:]:
                if flow.is_pair(other_flow):
                    num_growing_pair_flows += 1
        return [
            np.median(amount_packets) if len(amount_packets) else 0,
            np.median(amount_bytes) if len(amount_bytes) else 0,
            np.median(durations) if len(amount_bytes) else 0,
            ((2 * num_pair_flows) / num_flows) if num_flows > 0 else 0,
            (num_growing_flows - (2 * num_growing_pair_flows) / self.interval),
            len(self.growing_ports) / self.interval,
        ]

    def detect_growth(self):
        '''
        Reset variables for detecting growth of them
        '''
        self.growing_flows = dict()
        self.growing_ports = set()

    def write_data(self):
        six_tuple = self.calc_tuple()
        six_tuple.append(self.label)
        LOG.debug("Writing some training data")
        LOG.debug("Current tuple: %s", six_tuple)
        with open("training_data.txt", "a") as f:
            f.write(" ".join(map(str, six_tuple)) + "\n")
        LOG.debug("Written.")

    def clean_flows(self):
        current_time = time.time()
        del_indices = []
        for flow in self.flows.values():
            if (current_time - flow.time_last_used) > self.clean_interval:
               del_indices.append(str(flow))
        for del_index in del_indices:
            del self.flows[del_index]

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            LOG.warning("Ignoring incomplete packet")
        else:
            packet_in = event.ofp
            self.act_like_switch(packet, packet_in)


def launch():
    def start_switch(event):
        LOG.debug("Controlling %s with this", (event.connection,))
        Controller(
            event.connection,
            "--gen-data" in sys.argv,
            1 if "--attack" in sys.argv else 0,
            "--detect" in sys.argv
        )
    core.openflow.addListenerByName("ConnectionUp", start_switch)

if __name__ == '__main__':
    if "--train" in sys.argv:
        data, bin_labels = (lambda x: (x[:, :6], x[:, 6]))(np.loadtxt("training_data.txt"))
        labels = np.array([[1, 0] if l == 0 else [0, 1] for l in bin_labels])
        inputs = keras.Input(shape=(6,))
        x = keras.layers.Dense(10, activation=tf.nn.relu)(inputs)
        x = keras.layers.Dense(10, activation=tf.nn.relu)(x)
        outputs = keras.layers.Dense(2, activation=tf.nn.softmax)(x)
        model = keras.Model(inputs=inputs, outputs=outputs)
        model.compile(
            optimizer="RMSProp",
            loss=keras.losses.CategoricalCrossentropy()
        )
        history = model.fit(x=data, y=labels, epochs=500, verbose=1)
        print("Reached loss: {}".format(history.history['loss'][-1]))
        model.save("model.h5")
        print("Saved model as model.h5")
    else:
        boot(["log.level", "--DEBUG", "network_controller"])
