#!/usr/bin/env python

class Flags:
    """This class extracts features related to the TCP flags.

    """
    def __init__(self, feature):
        self.feature = feature
        self.flag_dict = {}
        self.synfin = 0

    def _get_flags(self) -> list:
        """The function returns a list of flag values as a sequence.

        Returns:
            list: Flag values.

        """
        feat = self.feature
        tcp_flags = feat.packet['TCP'].flags
        packets = feat.packets
        flag_list = list(tcp_flags for packet in packets)
        return flag_list


    #This method is left in but commented out for debbugging purposes
    # def get_flags(self) -> str:
    #     """This function returns the letter values of the sequence of strings

    #     Returns
    #         str: a letter sequence

    #     """

    #     #Convert the list to a string.
    #     flag_str = ' '.join(map(str, self._get_flags()))

    #     return flag_str

    def get_flag_total(self) -> int:
        """This feature counts the total number of flags in a flow.

        Returns:
            int: The total flag count

        """
        count = 0

        self.flag_dict.update({'NULL' : [0b00000000, 0]})
        emb_flags = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR']
        self.flag_dict.update({emb_flags[i]: [1 << i, 0] for i in range(8)})

        flags = self._get_flags()

        for curr_flag in flags:

            #bitwise comparisons

            if curr_flag == (self.flag_dict['NULL'][0]):

                self.flag_dict['NULL'][1] += 1


            if self.flag_dict['FIN'][0] == (self.flag_dict['FIN'][0] & curr_flag):

                self.flag_dict['FIN'][1] += 1


            if self.flag_dict['SYN'][0] == (self.flag_dict['SYN'][0] & curr_flag):

                self.flag_dict['SYN'][1] += 1


            if self.flag_dict['RST'][0] == (self.flag_dict['RST'][0] & curr_flag):

                self.flag_dict['RST'][1] += 1


            if self.flag_dict['PSH'][0] == (self.flag_dict['PSH'][0] & curr_flag):

                self.flag_dict['PSH'][1] += 1


            if self.flag_dict['ACK'][0] == (self.flag_dict['ACK'][0] & curr_flag):

                self.flag_dict['ACK'][1] += 1


            if self.flag_dict['URG'][0] == (self.flag_dict['URG'][0] & curr_flag):

                self.flag_dict['URG'][1] += 1


            if self.flag_dict['ECE'][0] == (self.flag_dict['ECE'][0] & curr_flag):

                self.flag_dict['ECE'][1] += 1


            if self.flag_dict['CWR'][0] == (self.flag_dict['CWR'][0] & curr_flag):

                self.flag_dict['CWR'][1] += 1


            if (self.flag_dict['SYN'][0] | self.flag_dict['FIN'][0]) == \
                 ((self.flag_dict['SYN'][0] | self.flag_dict['FIN'][0]) & curr_flag):

                self.synfin += 1


            count += 1

        return count


    def get_null_count(self) -> int:
        """Obtains the number of null flags

        Returns:
            The number of null flags.

        """

        return self.flag_dict['NULL'][1]


    #This group of methods represent
    #the single TCP flags
    def get_fin_count(self) -> int:
        """This feature counts the number of pure FIN flags in a flow.

        Returns:
            int: The FIN flag count

        """
        fin = 0x01
        count = self._get_flags().count(fin)

        return count

    def get_emb_fin_count(self) -> int:
        """Obtains the number of null flags

        Returns:
            The number of null flags.

        """


        return self.flag_dict['FIN'][1]

    def get_syn_count(self) -> int:
        """This feature counts the number of pure SYN flags
         in a flow.

        Returns:
            int: The SYN flag count

        """
        syn = 0x02
        count = self._get_flags().count(syn)

        return count

    def get_emb_syn_count(self) -> int:
        """Obtains the number of syn flags

        Returns:
            The number of syn flags.

        """

        return self.flag_dict['SYN'][1]


    def get_rst_count(self) -> int:
        """This feature counts the number of pure RST flags
         in a flow.

        Returns:
            int: The RST flag count

        """
        rst = 0x04
        count = self._get_flags().count(rst)

        return count

    def get_emb_rst_count(self) -> int:
        """Obtains the number of rst flags

        Returns:
            The number of rst flags.

        """

        return self.flag_dict['RST'][1]

    def get_psh_count(self) -> int:
        """This feature counts the number of pure PSH flags
         in a flow.

        Returns:
            int: The PSH flag count

        """
        psh = 0x08
        count = self._get_flags().count(psh)

        return count

    def get_emb_psh_count(self) -> int:
        """Obtains the number of rst flags

        Returns:
            The number of rst flags.

        """

        return self.flag_dict['PSH'][1]


    def get_ack_count(self) -> int:
        """This feature counts the number of pure ACK flags
         in a flow.

        Returns:
            int: The ACK flag count

        """
        ack = 0x10
        count = self._get_flags().count(ack)

        return count

    def get_emb_ack_count(self) -> int:
        """Obtains the number of ack flags

        Returns:
            The number of ack flags.

        """


        return self.flag_dict['ACK'][1]


    def get_urg_count(self) -> int:
        """This feature counts the number of pure URG flags
         in a flow.

        Returns:
            int: The URG flag count

        """
        urg = 0x20
        count = self._get_flags().count(urg)

        return count

    def get_emb_urg_count(self) -> int:
        """Obtains the number of urg flags

        Returns:
            The number of urg flags.

        """

        return self.flag_dict['URG'][1]


    def get_ece_count(self) -> int:
        """This feature counts the number of pure ECE flags
         in a flow.

        Returns:
            int: The ECE flag count

        """
        ece = 0x40
        count = self._get_flags().count(ece)

        return count

    def get_emb_ece_count(self) -> int:
        """Obtains the number of ece flags

        Returns:
            The number of ece flags.

        """

        return self.flag_dict['ECE'][1]


    def get_cwr_count(self) -> int:
        """This feature counts the number of pure CWR flags
         in a flow.

        Returns:
            int: The CWR flag count

        """
        cwr = 0x80
        count = self._get_flags().count(cwr)

        return count

    def get_emb_cwr_count(self) -> int:
        """Obtains the number of cwr flags

        Returns:
            The number of cwr flags.

        """

        return self.flag_dict['CWR'][1]


    #This group of methods represent some common
    #legal and illegal TCP flag combinations
    def get_synfin_count(self) -> int:
        """This feature counts the number of syn fin flags in a flow.

            note:
                This combination is a well known illegal combination
                that is almost always malicious.

        Returns:
            int: The syn/fin flag count

        """
        syn_fin = 0x03
        count = self._get_flags().count(syn_fin)

        return count

    def get_synack_count(self) -> int:
        """This feature counts the number of SYN/ACK flags in a flow.

        Returns:
            int: The SYN/ACK flag count

        """
        syn_ack = 0x12
        count = self._get_flags().count(syn_ack)

        return count

    def get_rstack_count(self) -> int:
        """This feature counts the number of RST ACK flags in a flow.

        Returns:
            int: The RST ACK flag count

        """
        rst_ack = 0x14
        count = self._get_flags().count(rst_ack)

        return count

    def get_pshack_count(self) -> int:
        """This feature counts the number of Push ACK flags in a flow.

        Returns:
            int: The Push ACK flag count

        """
        push_ack = 0x18
        count = self._get_flags().count(push_ack)

        return count

    def get_contain_finsyn_count(self) -> int:
        """This feature counts the number of fin syn counts
        that are embedded into TCP traffic with added flags
        to cloak the syn/fin combo

        Note:
            This method goes off the basis of the syn/fin combo
            representing 0x03 or 0b00000011 in decimal and any other combination
            being an even number. Thus the formula 2n+3

        Returns:
            int: The embedded syn/fin count

        """

        return self.synfin
