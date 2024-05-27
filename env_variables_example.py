# author: luciapintor90@gmail.com
# Rename this file as env_variables.py to change settings
import numpy as np

# this folder name is used to create 2 folders:
# _analysis: it contains merged files with different thresholds
# _dataset: it contains a pcap file for each channel filtered with the selected power threshold
input_folder_name_main = 'data'
input_folder_name_specific = 'A'
input_folder_name = '{}/{}'.format(input_folder_name_main, input_folder_name_specific)

# capture duration (used to scale plots)
duration = 20 * 60

# time window (in seconds) to consider a packet inside the window
delta_burst = 2

# different power thresholds for the analysis
power_th_start = -110
power_th_end = -20
step = 10
power_ths = np.arange(power_th_start, power_th_end, step)

# interfaces of the sniffer (to be removed from the pcap files)
embedded_interfaces = [
]

# if it is set to True, it discards all the non random mac addresses
only_random = False

# if it is set to True, it makes the analysis ('_analysis' folder)
# if it is set to False, it prepares data for the dataset ('_dataset' folder)
do_analysis = True

# select the threshold for the dataset version
dt_power_th = -60
