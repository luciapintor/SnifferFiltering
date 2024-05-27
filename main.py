# author: luciapintor90@gmail.com
from env_variables import *
from merge_pkt import merge_pkt, merge_ch
from analysis_ds import analysis_ths
from get_data_from_filename import group_filenames_same_capture
from statistics_ds import make_summary, pcap_statistics
from utils import create_missing_folder

if __name__ == '__main__':

    # manage folders
    analysis_folder_name = create_missing_folder('{}_analysis'.format(input_folder_name_main))
    dataset_folder_name = create_missing_folder('{}_dataset'.format(input_folder_name_main))

    analysis_folder_name_sub = create_missing_folder('{}/{}'.format(analysis_folder_name, input_folder_name_specific))
    dataset_folder_name_sub = create_missing_folder('{}/{}'.format(dataset_folder_name, input_folder_name_specific))

    # group files from the same capture (but different channel)
    file_groups = group_filenames_same_capture(folder_name=input_folder_name)

    summary_list = []

    if file_groups is not None:

        for g in file_groups:
            # get dictionary with lists of all packets (divided by channel) from the same capture
            # i.e. {1: [pkt1, pkt2, ...], 2: [pkt10, pkt11, ...]}
            all_packets = merge_pkt(capture_files=file_groups[g], input_folder_name=input_folder_name,
                                    embedded_interfaces=embedded_interfaces)

            # plot unfiltered pcap files
            pcap_statistics(folder_name=analysis_folder_name_sub, filename=g + "-unfiltered.png",
                            pkt_list=all_packets, duration=duration)
            print("Removed all APs and known interfaces in {}".format(file_groups[g]))

            # threshold analysis
            if do_analysis is True:
                tmp_summary, filtered_pkt = \
                    analysis_ths(all_packets=all_packets, capture_files=file_groups[g],
                                 output_folder_name=analysis_folder_name_sub, power_ths=power_ths,
                                 delta_burst=delta_burst, only_random=only_random, merged=True, duration=duration)

                print("Analysis ended in files {}".format(file_groups[g]))

                # join this capture summary to the summary list
                summary_list = summary_list + tmp_summary

            # re-frame as dataset: make a list for each channel
            tmp_summary, filtered_pkt = analysis_ths(all_packets=all_packets, capture_files=file_groups[g],
                                                     output_folder_name=dataset_folder_name_sub, power_ths=[dt_power_th],
                                                     delta_burst=delta_burst, only_random=only_random, merged=False,
                                                     duration=duration)

    if len(summary_list) > 1:
        make_summary(analysis_folder_name_sub, summary_list)
