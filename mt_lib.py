from discovery_lib import *

def mt_uptime(s: bytes) -> str:
    """ Convert bytestring to string representation of time
        (Mikrotik has a reversed order of bytes in uptime field)

    Args:
        s: source bytestring

    Returns:
        Days, hours, minutes and seconds of device uptime
    """
    return uptime_str_from4bytes(s[::-1])


def addresses(x: bytes) -> list:
    """ Creating a list of IPv4 addresses from a byte string

    Args:
        x: source bytesting

    Returns:
        A list of one or multiple IPv4 addresses
    """
    x = x[4:]
    addr: list = []
    while len(x) > 0:
        single_address: bytes = x[5:9]
        addr.append(ip_str_from4bytes(single_address))
        x = x[9:]
    return addr


def mgmt_address(x: bytes) -> dict:
    """ Creating a dictionary with management address information

    Args:
        x: source bytesting

    Returns:
        A management address information
    """
    adrlen: int = x[0]
    adrtype_i: int = x[1]
    address_b: bytes = x[2 : adrlen + 1]
    # IPv4
    if adrtype_i == 1:
        address: str = ip_str_from4bytes(address_b)
        adrtype: str = "IPv4"
    # IPv6
    elif adrtype_i == 2:
        address: str = ip6_str_from16bytes(address_b)
        adrtype: str = "IPv6"
    # 48bit MAC
    elif adrtype_i == 16389:
        address: str = mac_str_from6bytes(address_b)
        adrtype: str = "MAC"
    else:
        address = address_b.hex()
    x = x[adrlen + 1 :]
    interface_subt: int = x[0]
    interface_numb: int = to_int(x[1:5])
    oid_len: int = x[5]
    return {"address_type": adrtype, "address": address, "interface_subtype": interface_subt,
            "interface_number": interface_numb, "oid_len": oid_len}


def mac_phy(x: bytes) -> dict:
    """ MAC/PHY Configuration/Status decoding

    Args:
        x: source bytestring

    Returns:
        Information about PHY
    """
    auto_negotiation: dict = {}
    if (x[1] & 1) > 0:
        auto_negotiation["support"] = 1
    else:
        auto_negotiation["support"] = 0
    if (x[1] & 2) > 0:
        auto_negotiation["enabled"] = 1
    else:
        auto_negotiation["enabled"] = 0
    an_cap: list = an_capabilities(x[2:4])
    mau_type: str = mau_type_list[to_int(x[4:])]
    return {"auto_negotiation": auto_negotiation, "auto_negotiation_capabilities": an_cap,
            "mau_type": mau_type}


def mdi_power(x: bytes):
    """ Power Via MDI decode

    Args:
        x: source bytestring

    Returns:
        Information about power capabilities support
    """
    mdi: dict = {}
    if x[0] == 2:
        if (x[1] & 1) > 0:
            mdi["Port Class"] = "Power Source Equipment (PSE)"
        else:
            mdi["Port Class"] = "Powered Device (PD)"

        if (x[1] & 2) > 0:
            mdi["PSE MDI Power Support"] = 1
        else:
            mdi["PSE MDI Power Support"] = 0

        if (x[1] & 4) > 0:
            mdi["PSE MDI Power Enabled"] = 1
        else:
            mdi["PSE MDI Power Enabled"] = 0

        if (x[1] & 8) > 0:
            mdi["PSE Pairs Control Ability"] = 1
        else:
            mdi["PSE Pairs Control Ability"] = 0

        if x[2] == 1:
            mdi["PSE power_pair"] = "Signal pair"
        elif x[2] == 2:
            mdi["PSE power_pair"] = "Spare pair"

        if x[3] > 0:
            mdi["Power class"] = x[3] - 1

    return mdi


def aggregation(x: bytes) -> dict:
    """ Decode aggregation capabilities

    Args:
        x: source bytestring

    Returns:
        Information about aggregation capabilities
    """
    aggr: dict = {}
    if x[0] == 3:
        if (x[1] & 1) > 0:
            aggr["Aggregation Capability"] = 1
        else:
            aggr["Aggregation Capability"] = 0
        if (x[1] & 2) > 0:
            aggr["Aggregation Status"] = 1
        else:
            aggr["Aggregation Status"] = 0
        aggr["Aggregated Port ID"] = to_int(x[2:])
    return aggr


def int_without_first_byte(x: bytes) -> int:
    """ Remove a first byte of bytestring

    Args:
        x: source bytestring

    Returns:
        Bytestring without first byte
    """
    return to_int(x[1:])


def vlanname(x: bytes) -> dict:
    """ Decode VLAN information

    Args:
        x: source bytestring

    Returns:
        Information about VLAN
    """
    vlan_id: int = to_int(x[1:3])
    vlan_name: str = to_str(x[4:])
    return {"vlan_id": vlan_id, "vlan_name": vlan_name}


def prot_iden(x: bytes) -> str:
    """ Decode LLDP protocol identity

    Args:
        x: source bytestring

    Returns:
        Protocol ID
    """
    return to_hex(x[2:])


def mac_subtype(x: bytes) -> str:
    """ Decode MAC address from bytestring

    Args:
        x: source bytestring

    Returns:
        MAC address at string format
    """
    return mac_str_from6bytes(x[1:])


def chassis_subtype(x: bytes) -> dict:
    """ Decode chassis subtype

    Args:
        x: source bytestring

    Returns:
        Chassis subtype
    """
    if x[0] == 4:
        return {"MAC address": mac_subtype(x)}
    else:
        return {"Unknown subtype": x}


def port_subtype(x: bytes) -> dict:
    """ Decode port identifier

    Args:
        x: source bytestring

    Returns:
        Port identifier
    """
    if x[0] == 3:
        return {"MAC address": mac_subtype(x)}
    elif x[0] == 5:
        return {"Interface name": x[1:].decode()}
    else:
        return {"Unknown subtype": x}


def cdp_capabilities(b: bytes) -> list:
    """ Decode CDP capabilities

    Args:
        b:

    Returns:

    """
    cap: list = []
    i: int = (b[0] << 24) + (b[1] << 16) + (b[2] << 8) + b[3]
    cap_list = ['Router', 'Transparent bridge', 'Source Route Bridge', 'Switch', 'Host',
                'IGMP capable', 'Repeater', 'VoIP Phone', 'Remotely Managed Device',
                'CVTA/STP Dispute Resolution/Cisco VT Camera', 'Two Port Mac Relay']
    for bit in range(len(cap_list)):
        if (i & (2**bit) ) > 0:
            cap.append(cap_list[bit])
    return cap


def lldp_capabilities(b: bytes) -> dict:
    """ Decode LLDP capabilities

    Args:
        b:

    Returns:

    """
    c: list = ["supported", "enabled"]
    cap: dict = {c[0]: [], c[1]: []}
    # for example:  value b = b'\x00\x04\x00\x04'
    # (first two bytes - 'supported', less - 'enabled')
    cap_list: list = ["Other", "Repeater", "Bridge", "WLAN access point",
                      "Router", "Telephone", "DOCSIS cable device", "Station only"]
    for n in c:
        i: int = (b[0] << 8) + b[1]
        for bit in range(len(cap_list)):
            if (i & (2**bit) ) > 0:
                cap[n].append(cap_list[bit])
        b = b[2:]
    return cap


def an_capabilities(b: bytes) -> list:
    """ Decode autonegotiation capabilities

    Args:
        b: coded ***

    Returns:
        human readable ***
    """
    cap: list = []
    i: int = (b[0] << 8) + b[1]
    cap_list = ['1000BASE-T (full duplex mode)',
                '1000BASE-T (half duplex mode)',
                '1000BASE-X (-LX, -SX, -CX full duplex mode)',
                '1000BASE-X (-LX, -SX, -CX half duplex mode)',
                'Asymmetric and Symmetric PAUSE (for full-duplex links)',
                'Symmetric PAUSE (for full-duplex links)',
                'Asymmetric PAUSE (for full-duplex links)',
                'PAUSE (for full-duplex links)',
                '100BASE-T2 (full duplex mode)',
                '100BASE-T2 (half duplex mode)',
                '100BASE-TX (full duplex mode)',
                '100BASE-TX (half duplex mode)',
                '100BASE-T4',
                '10BASE-T (full duplex mode)',
                '10BASE-T (half duplex mode)',
                'Other or unknown']
    for bit in range(len(cap_list)):
        if (i & (2**bit) ) > 0:
            cap.append(cap_list[bit])
    return cap


def media_capabilities(b: bytes) -> list:
    cap: list = []
    i: int = (b[1] << 8) + b[2]
    cap_list = ['LLDP-MED Capabilities', 'Network Policy', 'Location Identification',
                'Extended Power via MDI-PSE', 'Extended Power via MDI-PD', 'Inventory']
    for bit in range(len(cap_list)):
        if (i & (2**bit) ) > 0:
            cap.append(cap_list[bit])
    return cap


mau_type_list = {
    0: "Other or unknown",
    2: "10BASE-5",
    3: "FOIRL",
    4: "10BASE-2",
    5: "10BASE-T duplex mode unknown",
    6: "10BASE-FP",
    7: "10BASE-FB",
    8: "10BASE-FL duplex mode unknown",
    9: "10BROAD36",
    10: "10BASE-T half duplex mode",
    11: "10BASE-T full duplex mode",
    12: "10BASE-FL half duplex mode",
    13: "10BASE-FL full duplex mode",
    14: "100BASE-T4",
    15: "100BASE-TX half duplex mode",
    16: "100BASE-TX full duplex mode",
    17: "100BASE-FX half duplex mode",
    18: "100BASE-FX full duplex mode",
    19: "100BASE-T2 half duplex mode",
    20: "100BASE-T2 full duplex mode",
    21: "1000BASE-X half duplex mode",
    22: "1000BASE-X full duplex mode",
    23: "1000BASE-LX half duplex mode",
    24: "1000BASE-LX full duplex mode",
    25: "1000BASE-SX half duplex mode",
    26: "1000BASE-SX full duplex mode",
    27: "1000BASE-CX half duplex mode",
    28: "1000BASE-CX full duplex mode",
    29: "1000BASE-T half duplex mode",
    30: "1000BASE-T full duplex mode",
    31: "10GBASE-X",
    32: "10GBASE-LX4",
    33: "10GBASE-R",
    34: "10GBASE-ER",
    35: "10GBASE-LR",
    36: "10GBASE-SR",
    37: "10GBASE-W",
    38: "10GBASE-EW",
    39: "10GBASE-LW",
    40: "10GBASE-SW",
    41: "10GBASE-CX4",
    42: "2BASE-TL",
    43: "10PASS-TS",
    44: "100BASE-BX10D",
    45: "100BASE-BX10U",
    46: "100BASE-LX10",
    47: "1000BASE-BX10D",
    48: "1000BASE-BX10U",
    49: "1000BASE-LX10",
    50: "1000BASE-PX10D",
    51: "1000BASE-PX10U",
    52: "1000BASE-PX20D",
    53: "1000BASE-PX20U",
    54: "10GBASE-T",
    55: "10GBASE-LRM",
    56: "1000BASE-KX",
    57: "10GBASE-KX4",
    58: "10GBASE-KR",
    59: "10/1GBASE-PRX-D1",
    60: "10/1GBASE-PRX-D2",
    61: "10/1GBASE-PRX-D3",
    62: "10/1GBASE-PRX-U1",
    63: "10/1GBASE-PRX-U2",
    64: "10/1GBASE-PRX-U3",
    65: "10GBASE-PR-D1",
    66: "10GBASE-PR-D2",
    67: "10GBASE-PR-D3",
    68: "10GBASE-PR-U1",
    69: "10GBASE-PR-U3",
    70: "40GBASE-KR4",
    71: "40GBASE-CR4",
    72: "40GBASE-SR4",
    73: "40GBASE-FR",
    74: "40GBASE-LR4",
    75: "100GBASE-CR10",
    76: "100GBASE-SR10",
    77: "100GBASE-LR4",
    78: "100GBASE-ER4",
    79: "1000BASE-T1",
    80: "1000BASE-PX30D",
    81: "1000BASE-PX30U",
    82: "1000BASE-PX40D",
    83: "1000BASE-PX40U",
    84: "10/1GBASE-PRX-D4",
    85: "10/1GBASE-PRX-U4",
    86: "10GBASE-PRD4",
    87: "10GBASE-PRU4",
    88: "25GBASE-CR",
    89: "25GBASE-CR-S",
    90: "25GBASE-KR",
    91: "25GBASE-KR-S",
    92: "25GBASE-R",
    93: "25GBASE-SR",
    94: "25GBASE-T",
    95: "40GBASE-ER4",
    96: "40GBASE-R",
    97: "40GBASE-T",
    98: "100GBASE-CR4",
    99: "100GBASE-KR4",
    100: "100GBASE-KP4",
    101: "100GBASE-R",
    102: "100GBASE-SR4",
    103: "2.5GBASE-T",
    104: "5GBASE-T",
    105: "100BASE-T1",
    106: "1000BASE-RHA",
    107: "1000BASE-RHB",
    108: "1000BASE-RHC",
    109: "2.5GBASE-KX",
    110: "2.5GBASE-X",
    111: "5GBASE-KR",
    112: "5GBASE-R",
    113: "10GPASS-XR",
    114: "25GBASE-LR",
    115: "25GBASE-ER",
    116: "50GBASE-R",
    117: "50GBASE-CR",
    118: "50GBASE-KR",
    119: "50GBASE-SR",
    120: "50GBASE-FR",
    121: "50GBASE-LR",
    122: "50GBASE-ER",
    123: "100GBASE-CR2",
    124: "100GBASE-KR2",
    125: "100GBASE-SR2",
    126: "100GBASE-DR",
    127: "200GBASE-R",
    128: "200GBASE-DR4",
    129: "200GBASE-FR4",
    130: "200GBASE-LR4",
    131: "200GBASE-CR4",
    132: "200GBASE-KR4",
    133: "200GBASE-SR4",
    134: "200GBASE-ER4",
    135: "400GBASE-R",
    136: "400GBASE-SR16",
    137: "400GBASE-DR4",
    138: "400GBASE-FR8",
    139: "400GBASE-LR8",
    140: "400GBASE-ER8",
    141: "10BASE-T1L",
    142: "10BASE-T1S half duplex mode",
    143: "10BASE-T1S multidrop mode",
    144: "10BASE-T1S full duplex mode",
}

