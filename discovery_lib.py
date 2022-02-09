from functools import reduce


def ip_str_from4bytes(s: bytes) -> str:  # b'\xc0\xa8\xfa\xe5' => 192.168.250.229
    """ Convert bytestring to string representation of IPv4 address

    Args:
        s: source bytestring

    Returns:
        IPv4 address in traditional notation
    """
    return str(s[0]) + "." + str(s[1]) + "." + str(s[2]) + "." + str(s[3])


def ip6_str_from16bytes(s: bytes) -> str:
    """ Convert bytestring to string representation of IPv6 address

    Args:
        s: source bytestring

    Returns:
        IPv6 address in traditional notation
    """
    m = [f"{b:02x}" for b in s]
    r = ""
    for i in range(16):
        r = r + ":" + m[i] if (i % 2 == 0 and i != 0) else r + m[i]
    return r.replace("0000", "").replace("::", ":")


def mac_str_from6bytes(s: bytes) -> str:  # b'\xdc\x9f\xdb:\xa7h'
    """ Convert bytestring to string representation of MAC address

    Args:
        s: source bytestring

    Returns:
        MAC address in traditional notation
    """
    m = [f"{z:02x}" for z in s]
    return reduce(lambda res, x: res + ":" + x, m).replace("0x", "")


def uptime_str_from4bytes(uptime: bytes) -> str:  # b'\x00\n\xab\xa2'
    """ Convert bytestring to string representation of time

    Args:
        uptime: source bytestring

    Returns:
        Days, hours, minutes and seconds of device uptime
    """
    t = int(uptime.hex(), 16)
    d = int(t / 86400)
    h = int((t - 86400 * d) / 3600)
    m = int((t - 3600 * h - 86400 * d) / 60)
    s = int(t - d * 86400 - h * 3600 - m * 60)
    ss = ""
    if d > 0:
        ss += f"{d}d"
    if h > 9 or d > 0:
        ss += f"{h:02}h"
    elif h > 0:
        ss += f"{h:2}h"
    if m > 9 or len(ss) > 0:
        ss += f"{m:02}m"
    elif m > 0:
        ss += f"{m:2}m"
    ss += f"{s:02}s"
    return ss


def to_str(x):
    return x.decode()


def to_hex(x):
    return x.hex()


def to_int(x):
    return int(x.hex(), 16)


def exist(param) -> bool:
    """ Check parameter existence"""
    return not param is None
    # return False if param is None else True


def tlv_dissect(data: bytes, schema: str) -> tuple:
    """ Extracts the first field from a byte string,
        depending on the protocol type

    Args:
        data: input bytestring
        schema: decoding schema

    Returns:
        Extracted field value, type of field, rest of bytestring
    """
    if schema == "ubnt":
        ftype: int = data[0]
        length: int = (data[1] << 8) + data[2]
        value: bytes = data[3 : length + 3]
        unprocessed_data: bytes = data[length + 3 :]

    elif schema == "mndp":
        ftype: int = (data[0] << 8) + data[1]
        length: int = (data[2] << 8) + data[3]
        value: bytes = data[4 : length + 4]
        unprocessed_data: bytes = data[length + 4 :]

    elif schema == "cdp":
        ftype: int = (data[0] << 8) + data[1]
        length: int = (data[2] << 8) + data[3]
        value: bytes = data[4:length]
        unprocessed_data: bytes = data[length:]

    elif schema == "lldp":
        # two first byte: 7 bit - type and 9 bit - length
        ftype: int = (254 & data[0]) >> 1
        length: int = ((data[0] & 1) << 8) + data[1]
        value: bytes = data[2 : length + 2]
        unprocessed_data: bytes = data[length + 2 :]
    return ftype, value, unprocessed_data


def remove_duplicates(data: list) -> list:
    """ Remove duplicated elements from list

    Args:
        data: incoming data with duplicates

    Returns:
        Cleaned data
    """
    result: list = []
    devices: dict = {}

    for element in data:
        if element["protocol"] == "ubnt":
            devices[element["macaddr"]] = element
        elif element["protocol"] == "mndp":
            devices[element["MAC-Address"]] = element
        elif element["protocol"] == "cdp":
            if "Addresses" in element:
                devices[element["Device ID"] + str(element["Addresses"])] = element
            else:
                devices[element["Device ID"]] = element
        else: # lldp
            devices[str(element["Chassis Subtype"]) + str(element["Port Subtype"])] = element
    result.extend(devices.values())
    return result


