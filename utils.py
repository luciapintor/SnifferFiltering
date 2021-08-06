import os

from numpy import ceil


def create_missing_folder(folder_name):
    """
    This function create a folder if it does not exist.
    """
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    return folder_name


def get_7th(mac):
    """
    This function returns the seventh bit of a mac address.
    :param mac:
    :return:
    """
    # decimal value
    d_first_octet = int(mac[:2], 16)

    # avoid errors if there are less than 2 digits
    if d_first_octet < 2:
        return 0

    first_octet = bin(d_first_octet)
    return int(first_octet[-2])


def frequency2channel(frequency):
    """
    Given a frequency in MHz, the Wi-Fi channel is returned.
    :param frequency:
    :return:
    """
    step = 5  # MHz
    offset = 2412.0 - (step / 2)  # minimum

    if frequency <= offset:
        # it could be in ch 1 or out of range
        return 1
    elif frequency > 2483:
        return 14
    else:
        return int(ceil((frequency - offset) / step))
