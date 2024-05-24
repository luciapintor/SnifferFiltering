# author: luciapintor90@gmail.com
import numpy as np
from scapy.all import wrpcap

from get_data_from_filename import find_file_group, find_caption_mode
from merge_pkt import merge_ch
from statistics_ds import pcap_statistics
from utils import get_7th


def analysis_ths(all_packets=None, capture_files=None, output_folder_name='data_analysis', power_ths=None,
                 delta_burst=2, merged=False, only_random=False, duration=1200):
    """
    This function gets all the packets from pkt_list (in which packets are separated by channel) and,
    for each of them creates different files, in the output folder,in which only MAC address packets that,
    at least once, had a power value over the thresholds (power_ths) are copied.
    This process is repeated for different thresholds and at the end a csv report is created.
    If only_random is true, then all non-random mac addresses are discarded.
    :param all_packets:
    :param capture_files:
    :param output_folder_name:
    :param power_ths:
    :param delta_burst:
    :param merged:
    :param only_random:
    :param duration:
    :return:

    """

    # manage default threshold
    if power_ths is None:
        power_ths = np.arange(-40, -80, 10)

    # The summary list is used to create a summary file and plot.
    summary_list = []

    filtered_pkt = []

    # filter with different thresholds
    for power_th in power_ths:
        filtered_pkt = clean_all_packets(all_packets=all_packets, output_folder_name=output_folder_name,
                                         capture_files=capture_files, power_th=power_th,
                                         delta_burst=delta_burst, merged=merged, only_random=only_random)
        if len(capture_files) > 0:
            filename = capture_files[0]
        else:
            filename = capture_files

        file_group = find_file_group(filename)

        # make plots
        over_th_mac = pcap_statistics(folder_name=output_folder_name,
                                      filename=file_group + "-th{}".format(power_th),
                                      pkt_list=filtered_pkt, duration=duration)

        # summary statistics of the f file
        summary_list.append({
            'file group': file_group,  # file group
            'MAC': over_th_mac,  # list of mac over threshold
            '#MAC': len(over_th_mac),  # number of mac over threshold
            'device mode': find_caption_mode(filename),  # smartphone mode
            'power th': power_th})  # power threshold

    return summary_list, filtered_pkt


def clean_all_packets(all_packets, output_folder_name, capture_files, power_th, delta_burst, merged, only_random=False):
    """
    This function gets packets from all_packets, checks which mac address, has a power value over the threshold or
    is close to a burst, and creates a new file in the output folder with their packets.
    If only_random is true, then all non-random mac addresses are discarded.
    :param all_packets:
    :param output_folder_name:
    :param capture_files:
    :param power_th:
    :param delta_burst:
    :param merged:
    :param only_random:
    :return:
    """
    over_th_mac = get_over_th_interfaces(pkt_list=all_packets, power_th=power_th)
    filtered_pkt = {}

    for ch_pkt in all_packets:
        for pkt in all_packets[ch_pkt]:
            # organize filtered_pkt as all_packets
            if ch_pkt not in filtered_pkt:
                filtered_pkt[ch_pkt] = []

            # filter and append
            try:
                mac = pkt.addr2
                if mac in over_th_mac:
                    for timestamp in over_th_mac[mac]:
                        # check if that packet could be considered inside a burst through a time delta
                        delta = get_delta(pkt.time, timestamp)

                        if delta < delta_burst:
                            if only_random is False:
                                filtered_pkt[ch_pkt].append(pkt)

                            elif get_7th(mac) > 0:
                                # if the 7th bit is set to 1, then mac address is randomly generated
                                filtered_pkt[ch_pkt].append(pkt)

                            # this packet was inside a burst, stop the loop after adding it to the list
                            break

            except:
                print('error in clean_pcap_file')

    if len(capture_files) >= 1:
        if merged is True:
            filename = '{}/{}-ch-merged-th{}.pcap'.format(output_folder_name, find_file_group(capture_files[0]),
                                                          power_th)
            wrpcap(filename, merge_ch(filtered_pkt))
        else:
            for ch_pkt in filtered_pkt:
                filename = '{}/{}-ch-{}-th{}.pcap'.format(output_folder_name, find_file_group(capture_files[0]),
                                                          ch_pkt, power_th)
                wrpcap(filename, filtered_pkt[ch_pkt])

    return filtered_pkt


def get_over_th_interfaces(pkt_list, power_th):
    """
    This function gets a dictionary of mac addresses and relative timestamps in packets
    with power level over the threshold in the file named filename, inside the folder named folder_name.
    :param pkt_list:
    :param power_th:
    :return:
    """
    over_th = {}

    for ch_pkt in pkt_list:
        for pkt in pkt_list[ch_pkt]:
            # get the antenna signal power
            power = pkt.dBm_AntSignal

            if power > power_th:
                # if it is over the power threshold, then add it to the list with its timestamp
                try:
                    mac = pkt.addr2

                    if mac not in over_th:
                        over_th[mac] = []

                    over_th[mac].append(float(pkt.time))

                except:
                    print('error in get_over_th_interfaces')

    return over_th


def get_delta(t1, t2):
    """
    This function gets the absolute value of the difference between two float numbers.
    :param t1:
    :param t2:
    :return:
    """
    delta = float(t1) - float(t2)
    if delta < 0:
        return -delta
    return delta
