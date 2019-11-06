class IpBased: 
    def __init__(self, feature):
        self.ip_addr = feature._get_dest_ip()

    def is_google(self) -> bool:
        """Determines if an IP address is a known google IPv4 address

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