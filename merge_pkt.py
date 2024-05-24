# author: luciapintor90@gmail.com
from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11ProbeReq, Dot11ProbeResp, Dot11Beacon, Dot11AssoResp
from utils import frequency2channel


def merge_pkt(capture_files, input_folder_name, embedded_interfaces=None):
    """
    This function merges all the packets related to the same capture.
    Usually there are 3 files for each capture referring respectively to channels 1, 6, and 11.
    The output is a dictionary that uses as key the channel id and as value the list of packets of the file.
    This function also removes the mac addresses listed as embedded_interfaces.
    :param capture_files:
    :param input_folder_name:
    :param embedded_interfaces:
    :return:
    """

    if embedded_interfaces is None:
        embedded_interfaces = []

    all_packets = {}

    if capture_files is not None:
        all_packets_unfiltered = get_all_packets_unfiltered(capture_files, input_folder_name)

        # find all Access Points of this group of pcap
        ap_list = get_ap_macs(all_packets_unfiltered)

        for ch_pkt in all_packets_unfiltered:
            if ch_pkt not in all_packets:
                all_packets[ch_pkt] = []
            for pkt in all_packets_unfiltered[ch_pkt]:
                try:
                    mac = pkt.addr2
                    if mac not in ap_list and mac not in embedded_interfaces:
                        # if it is not an AP
                        if pkt.haslayer(Dot11ProbeReq):
                            # if it is a probe request
                            all_packets[ch_pkt].append(pkt)

                except:
                    print('error in merging file {}'.format(capture_files))

        return all_packets


def get_all_packets_unfiltered(file_group, input_folder_name):
    """
    This function, given a group of pcap files, gets all the packets.
    :param file_group:
    :param input_folder_name:
    :return:
    """
    all_packets_unfiltered = {}

    for f in file_group:

        # append all the packets of this group in the list
        file_path = '{}/{}'.format(input_folder_name, f)

        for pkt in rdpcap(file_path):

            # get the channel
            ch = frequency2channel(pkt.Channel)

            if ch not in all_packets_unfiltered:
                all_packets_unfiltered[ch] = []

            all_packets_unfiltered[ch].append(pkt)

    return all_packets_unfiltered


def get_ap_macs(all_packets_unfiltered):
    """
    This function, given a packet list, gets all the access point mac addresses.
    :param all_packets_unfiltered:
    :return:
    """
    ap_list = []

    for ch_pkt in all_packets_unfiltered:
        for pkt in all_packets_unfiltered[ch_pkt]:
            if has_ap_layer(pkt) is True:
                # it is an Access Point packet
                ap_list.append(pkt.addr2)

    return ap_list


def has_ap_layer(pkt):
    """
    This function checks if a packet is sent by an Access Point.
    """
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp) or pkt.haslayer(Dot11AssoResp):
        # if this packet has layer beacon, or probe response or association response
        if hasattr(pkt, 'addr2'):
            # it is an Access Point packet
            return True
    return False


def merge_ch(all_packets):
    """
    This function merges all packets from different channels in a single list.
    :return:
    """

    merged_pkt = []
    for ch_pkt in all_packets:
        merged_pkt = merged_pkt + all_packets[ch_pkt]

    return merged_pkt
