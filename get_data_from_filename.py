# author: luciapintor90@gmail.com
import os
from datetime import datetime


def group_filenames_same_capture(folder_name='data'):
    """
    This function groups all the files that have the same datetime, but different channels.
    :param folder_name:
    :return:
    """

    file_groups = {}
    for f in os.listdir(folder_name):
        if '-ch' in f:
            # separate the datetime from other infos (channel and mode)
            fg = find_file_group(f)

            if fg not in file_groups:
                # it didn't find other files with this datetime
                file_groups[fg] = [f]
            else:
                # it found other files with this datetime
                file_groups[fg].append(f)

    return file_groups


def find_caption_mode(filename):
    """
    This function returns the mode in a filename that has the following structure name:
    A-ts-2021-Apr-12-h12-m13-s57-ch6-modeS.pcap
    :param filename:
    :return:

    example: filename: A-ts-2021-Apr-12-h12-m13-s57-ch6-modeS.pcap
    It will return "S"
    """
    filename = filename.replace('.pcap', '')
    start_str, end_str = filename.split('-mode')
    splitted_end = end_str.split('-')
    caption_mode = splitted_end[0]
    return caption_mode


def get_filename_timestamp(filename):
    """
    This function returns the timestamp in a filename that has the following structure name:
    A-ts-2021-Apr-12-h12-m13-s57-ch6-modeS.pcap
    :param filename:
    :return:

    example: filename: A-ts-2021-Apr-12-h12-m13-s57-ch6-modeS.pcap
    It will return the float timestamp of "2021-Apr-12-h12-m13-s57"
    """

    try:

        start = 'ts-'
        id_start = filename.find(start) + len(start)
        id_end = id_start + 23  # len ('2021-Apr-12-h12-m13-s57')

        # here the timestamp
        timestamp_dt = datetime.strptime(filename[id_start:id_end], '%Y-%b-%d-h%H-m%M-s%S')
        return timestamp_dt.timestamp()

    except:
        return 0.0


def find_power_th(filename):
    """
    This function returns the power threshold in a filename that has the following structure name:
    A-ts-2021-Apr-12-h12-m13-s57-merged-modeS-th-30.pcap
    :param filename:
    :return:

    example: filename: A-ts-2021-Apr-12-h12-m13-s57-merged-modeS-th-30.pcap
    It will return -30
    """

    if '-th' in filename:
        start = '-th'
        id_start = filename.find(start) + len(start)
        id_end = filename.find('.pcap')

        # here the power threshold
        power_th = int(filename[id_start:id_end])
        return power_th

    else:
        return 0


def find_file_group(filename):
    """
    This function returns the file group in a filename that has the following structure name:
    A-ts-2021-Apr-12-h12-m13-s57-merged-modeS-th-30.pcap
    :param filename:
    :return:

    example: filename: A-ts-2021-Apr-12-h12-m13-s57-merged-modeS-th-30.pcap
    It will return "A-ts-2021-Apr-12-h12-m13-s57-merged"
    """

    filename = filename.replace('.pcap', '')

    if '-th' in filename:
        starting, ending = filename.split('-th')
    else:
        starting, ending = filename.split('-ch')
        e1, e2 = ending.split('-mode')
        starting = starting + '-mode' + e2
    return starting
