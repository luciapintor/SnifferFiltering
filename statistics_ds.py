# author: luciapintor90@gmail.com
import pandas as pd
from matplotlib import pyplot as plt

from get_data_from_filename import get_filename_timestamp
from utils import create_missing_folder


def pcap_statistics(folder_name, filename, pkt_list, duration):
    """
    This function
    :param folder_name:
    :param filename:
    :param pkt_list:
    :param duration:
    """

    columns = ['power', 'timestamp']
    mac_dict = {}

    for ch_pkt in pkt_list:
        for pkt in pkt_list[ch_pkt]:

            mac_id = pkt.addr2

            if ch_pkt not in mac_dict:
                mac_dict[ch_pkt] = {}

            if mac_id not in mac_dict[ch_pkt]:
                mac_dict[ch_pkt][mac_id] = []

            mac_dict[ch_pkt][mac_id].append([pkt.dBm_AntSignal, float(pkt.time)])

    offset = get_filename_timestamp(filename)

    # make plots
    single_channel_folder_name = create_missing_folder('{}/single_channel'.format(folder_name))
    single_channel_plots(mac_dict, columns, single_channel_folder_name, filename, offset, duration)

    three_channels_folder_name = create_missing_folder('{}/three_channels'.format(folder_name))
    three_channels_plots(mac_dict, columns, three_channels_folder_name, filename, offset, duration)

    # get the mac list
    over_th_mac = []
    for ch in mac_dict:
        over_th_mac = over_th_mac + list(mac_dict[ch].keys())

    # remove duplicates
    over_th_mac = list(dict.fromkeys(over_th_mac))

    return over_th_mac


def single_channel_plots(mac_dict, columns, folder_name, filename, offset, duration):
    """
    This function plots all the elements of the mac_dict dictionary (labeled with the columns vector) and
    saves the graphs as png images in the folder folder_name, and file name filename.
    Variables offset and duration are respectively used for the x-offset and for the x-axis max value.
    A different graph is made for each channel.
    :param mac_dict:
    :param columns:
    :param folder_name:
    :param filename:
    :param offset:
    :param duration:
    """
    if len(mac_dict) > 0:
        for channel in mac_dict:
            fig = plt.figure(figsize=(40, 8))
            axs = fig.add_subplot(111)

            for mac in mac_dict[channel]:
                dt = pd.DataFrame(mac_dict[channel][mac], columns=columns)
                ts = dt['timestamp']
                pw = dt['power']
                axs.scatter(x=(ts - offset), y=pw, label=mac)

            plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
            plt.xlim(0, duration)

            # set axis names
            axs.set_xlabel('time (seconds)')
            axs.set_ylabel('power (dBm)')
            axs.set_title('Channel {}'.format(channel))

            # save the plot
            plt.savefig('{}/{}-ch{}.png'.format(folder_name, filename.replace('.pcap', ''), channel))


def three_channels_plots(mac_dict, columns, folder_name, filename, offset, duration):
    """
    This function plots all the elements of the mac_dict dictionary (labeled with the columns vector) and
    saves the graphs as png images in the folder folder_name, and file name filename.
    Variables offset and duration are respectively used for the x-offset and for the x-axis max value.
    All channels are plotted in the same file.
    :param mac_dict:
    :param columns:
    :param folder_name:
    :param filename:
    :param offset:
    :param duration:
    """
    if len(mac_dict) > 1:
        channel_num = len(mac_dict)
        fig, axs = plt.subplots(channel_num, figsize=(40, 30))

        i = 0
        for channel in sorted(mac_dict):
            for mac in mac_dict[channel]:
                dt = pd.DataFrame(mac_dict[channel][mac], columns=columns)
                ts = dt['timestamp']
                pw = dt['power']
                axs[i].scatter(x=(ts - offset), y=pw, label=mac)
                axs[i].legend(loc='upper left', bbox_to_anchor=(1.05, 1))
                axs[i].set_title('Channel {}'.format(channel))

                # x-axis limits (to have the same offset in all graphs)
                axs[i].set_xlim([0, duration])

                # set axis names
                axs[i].set_xlabel('time (seconds)')
                axs[i].set_ylabel('power (dBm)')

            i += 1
            if i > channel_num:
                break

        # save the plot
        plt.savefig('{}/{}-allch.png'.format(folder_name, filename.replace('.pcap', '')))


def make_summary(folder_name, summary_list):
    """
    This function make a summary of the summary list and saves is in the folder_name folder.
    The summary consists in a csv file and a plot.
    :param folder_name:
    :param summary_list:
    :return:
    """

    # get columns names
    if len(summary_list) > 1:
        columns = summary_list[1].keys()
    else:
        columns = []

    df = pd.DataFrame(summary_list, columns=columns)

    # save the csv
    df.to_csv('{}/summary.csv'.format(folder_name))

    # plot data
    fig, ax = plt.subplots()

    # order by power threshold
    df = df.sort_values(by='power th')

    # labels are grouped by file group and then by mode
    for file_group, f_gp in df.groupby('file group'):
        for mode, m_gp in f_gp.groupby('device mode'):
            m_gp.plot(x='power th', y='#MAC', ax=ax, label=mode)

    # set axis names
    ax.set_xlabel('power th (dBm)')
    ax.set_ylabel('#mac')

    # save the plot
    plt.savefig('{}/summary.png'.format(folder_name))


