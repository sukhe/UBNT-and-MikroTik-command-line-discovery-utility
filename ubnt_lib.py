from discovery_lib import *

def wmode(x: bytes) -> str:
    """ Wireless mode decoding

    Args:
        x: byte encoded representation of wireless mode

    Returns:
        String representation of wireless mode
    """
    if x == b"\x02":
        return "sta"
    elif x == b"\x03":
        return "ap"
    return ""


def ipinfo(x: bytes) -> dict:
    """ Get MAC and IPv4 addresses

    Args:
        x: raw binary format of addresses

    Returns:
        Dictionary with IPv4 and MAC addresses matching
    """
    mac = mac_str_from6bytes(x[:6])
    ip = ip_str_from4bytes(x[6:])
    return {ip: mac}


def group_by_essid(data: list) -> tuple:
    """ Grouping devices with the same ESSID
        Devices without wifi will be added to the 'non_wireless' list

    Args:
        data: list of devices

    Returns:
        Wireless devices in a dictionary, non_wireless devices in a list
    """
    wireless: dict = {}
    non_wireless: list = []
    for item in data:
        if "essid" in item:
            if item["essid"] in wireless:
                wireless[item["essid"]].update(
                    {item["hostname"]: [item["wmode"], list(item["ipinfo"].keys())]}
                )
            else:
                wireless[item["essid"]] = {
                    item["hostname"]: [item["wmode"], list(item["ipinfo"].keys())]
                }
        else:  # There are UBNT switches that don't have an ESSID
            non_wireless.append([item["hostname"], list(item["ipinfo"].keys())])
    return wireless, non_wireless


def tree_view(data: list) -> list:
    """ Prepare data for viewing a list of wireless devices as a tree

    Args:
        data: list of decoded data

    Returns:
        List of strings, prepared for output

    Example:
         > AP1-SSID
         =================================
         # Access_Point1_Name             ['192.168.1.1']
           + Client1_Station_Name         ['192.168.1.15']
           + Client2_Station_Name         ['192.168.1.16', '10.20.30.16']

         > AP2-SSID
         =================================
         # Access_Point2_Name             ['192.168.2.1']
           + Client3_Station_Name         ['192.168.2.15']
           + Client4_Station_Name         ['192.168.2.56']
    """

    result: list = []

    wireless, non_wireless = group_by_essid(data)

    # Select on each cycle all stations and ap with equal ESSID
    for essid in wireless:
        # Sort order: "ap", "sta", "sta", "sta" ...
        wireless[essid] = sorted(wireless[essid].items(), key=lambda x: x[1][0])

        result.append("\n> " + essid + "\n=================================")
        if wireless[essid][0][1][0] == "ap":
            result.append(
                f"# {wireless[essid][0][0]:27}    {str(wireless[essid][0][1][1])}"
            )
            del wireless[essid][0]
        else:
            # If discovery service disabled on the AP or response packet was lost
            result.append("* Response from AP don't received")
        if len(wireless[essid]) > 0:
            for sta in wireless[essid]:
                result.append(f"  + {sta[0]:26}   {str(sta[1][1])}")

    if len(non_wireless) > 0:
        result.append("\n< NON-WIRELESS \n=================================")
        for nw in non_wireless:
            result.append(f": {nw[0]:26}   {str(nw[1])}")
    return result
