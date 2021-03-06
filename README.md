# SnifferFiltering

This script performs a power filtering of pcap files, exploiting the transmission pattern of probe requests, which are sent in batches during short time windows, that we will call bursts later on. 

Additionally packets from known sources using factory mac addresses (i.e. embedded interfaces of the sniffer) can be excluded by adding their macs to the embedded_interfaces list in the env_variables.py file. The other main parameters of the algorithm can also be modified via this file.

This algorithm is specifically designed to replicate the conditions of isolation of an anechoic chamber under particular conditions, i.e. during the capture the sniffer must be very close to the device to be analysed (10 - 20 cm), and there must be no other sources of random Wi-Fi packets within two metres. 

This filtering was necessary to carry out the realization of an Open Source database that collects probe request ground truth signatures of individual smartphones (various models and operating systems) that randomise their MAC address.

The present script has been tested and verified using as input the outputs of our [WiFi-Sniffer script](https://github.com/luciapintor/WiFi-Sniffer), that uses a file naming structure that specifies device ID, timestamp, mode and channel (i.e. A-ts-2021-May-21-h11-m57-s24-modeS-ch-1.pcap). 

By running the sniffing algorithm, it is possible to collect data on several channels contemporaneously: the names of the generated files will be almost identical, except for the last portion that refers to the channel. This allows us to easily group all files referring to the same capture.

By running the main.py script, the programme 1) groups together files referring to the same capture, and 2) converts them into a Python structure for the next steps, 3) the filtering and 4) the creation of graphs and statistics.

## Group file names
The main function in the file get_data_from_filename.py is group_filenames_same_capture, which carries out the following steps:

1) Generate a dictionary where the key is the common portion of the file names in each group of files from the same capture, and the value is the list of file names of the group.
 
2) Given the name of the capture folder, analyse the file names (of .pcap files), to group those referring to the same capture but different channels   (same device, mode and timestamp).
 
3) For each file, check whether it can be associated with one of the keys in the dictionary, otherwise add a new key in the dictionary and create the new list.

This file also contains functions to get the following information from the title: caption mode, timestamp, filter power threshold.

## Convert data in Python structures
The main function in the file merge.py is merge_pkt, that can be broken down in the following steps:

1) Extract data from each file .pcap in the same group and merge it in a single Python structure (get_all_packets_unfiltered).
 
2) The preparation for the filtering includes the creation of the Access Points (APs) MAC list (get_ap_macs): APs are identifiable because they emit beacon packets in addition to probe requests. Packets with MAC addresses in the AP list are discarded. Other discarded packets are the ones that have a MAC address that is inside the embedded devices list, an input list selected by the user through the env_variables.py file.
 
3) Generate a dictionary where the key is the capture channel, and the value is the packet list of .pcap files collected in that channel. Each Probe Request packet is examined and copied to the list referring to its acquisition channel, if its mac is not present in either the AP, or the embedded devices lists.

## Power threshold filtering
Function analysis_ths in the file analysis_ds.py follows these steps:

1) It detects packets with power level over the defined threshold and creates a list of their mac addresses and timestamps (get_over_th_interfaces).
 
2) With function clean_all_packets it re-analyses all packets in the files, referring to a single capture, and saves only those packets that have the mac address in the list defined in step 1) and that have a temporal distance lower than a user-defined delta from the timestamp (or timestamps) paired with that mac. Other packets are dropped.
 
3) It calls functions to generate graphs and statistics.

## Statistics and chart generation
Functions in the file statistics.py do the following steps:

1) The pcap_statistics function reorganises data as a Dataframe structure to make it conform to other functions of this file.
 
2) The data structure is used to graph the captures' data both as a single channel and as the three channels together (respectively single_channel_plots and three_channels_plots functions). The x-axis of each graph represents time in seconds, and the y-axis represents packet power level in dBm.

3) Finally, the list of mac addresses remaining after filtering is created and returned.

## Utilities
The file utils.py contains some functions that can be used also independently:

1) create_missing_folder - it creates a folder with the input name, if it does not exist.
2) get_7th - given a mac address, it returns the seventh bit value.
3) frequency2channel - given a frequency it returns the Wi-Fi channel number.


## Environment variables
File env_variables_example.py is an example of how the env_variables.py file (excluded with gitignore) should look like. Example file is meant to be copied and renamed correctly, in order to change the values of the input variables as desired.

## Requirements
The algorithm requires the installation of `numpy`, `pandas`, `matplotlib`,
and `scapy` libraries through pip.

`pip install numpy`

`pip install pandas`

`pip install matplotlib`

`pip install scapy`



