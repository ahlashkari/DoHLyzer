class IpBased:
    """This class checks the flow destination IP against lists of IP addresses.

    """
    def __init__(self, feature):
        self.ip_addr = feature.dest_ip

    def is_google(self) -> bool:
        """Determines if an IP address is a known google IPv4 address

        Note:
            This is intended as a sort of non-comprehensive white list.

        Returns:
            bool: True if it is a google IPv4.
            False if otherwise.

        """
        is_google = ('64.233.160.0' <= self.ip_addr <= '64.233.191.255') \
        or ('66.102.0.0' <= self.ip_addr <= '66.102.15.255') \
        or ('66.249.64.0' <= self.ip_addr <= '66.249.95.255') \
        or ('72.14.192.0' <= self.ip_addr <= '72.14.255.255') \
        or ('74.125.0.0' <= self.ip_addr <= '74.125.255.255') \
        or('209.85.128.0' <= self.ip_addr <= '209.85.255.255') \
        or ('216.239.32.0' <= self.ip_addr <= '216.239.63.255')

        return is_google

    def is_bad(self) -> bool:
        """Determines if an IP address is a known malicious IPv4 address

        Note:
            This is intended as a sort of non-comprehensive white list.
            Addresses used are from https://unit42.paloaltonetworks.com/rockein-the-netflow/

        Returns:
            bool: True if it is a malicious IPv4.
            False if otherwise.

        """
        ip_a = self.ip_addr
        is_bad = ip_a in ('43.224.225.220', '67.21.64.34', \
            '103.52.216.35', '104.248.53.213', '104.238.151.101', \
            '198.204.231.250', '205.185.122.229')

        return is_bad
