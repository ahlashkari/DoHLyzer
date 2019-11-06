#!/usr/bin/env python

class Flags:
    """This class extracts features related to the TCP flags.

    """
    def __init__(self,feature):
        self.feature = feature 

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


    def get_flags(self) -> str:
        """This function returns the letter values of the sequence of strings

        Returns
            str: a letter sequence

        """

        #Convert the list to a string.
        flag_str = ' '.join(map(str, self._get_flags()))

        return flag_str

    def get_flag_total(self) -> int:
        """This feature counts the total number of flags in a flow.

        Returns:
            int: The total flag count

        """

        count = 0
        flags = self._get_flags()
        for curr_flag in flags:
            count += 1


        return count


    def get_null_count(self) -> int:
        """Obtains the number of null flags

        Returns:
            The number of null flags.

        """

        null = 0b00000000

        count = 0

        flags = self._get_flags()
        for curr_flag in flags:

            #returns true if the bits that are in common
            #are the same as null
            if (curr_flag == null):
                count += 1 

        return count    


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

        fin = 0b00000001

        count = 0

        flags = self._get_flags()
        for curr_flag in flags:

            #returns true if the bits that are in common
            #are the same as fin
            if ((curr_flag & fin) == fin):
                count += 1 

        return count 

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

        syn = 0b00000010

        count = 0

        flags = self._get_flags()
        for curr_flag in flags:

            #returns true if the bits that are in common
            #are the same as fin
            if ((curr_flag & syn) == syn):
                count += 1 

        return count 

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

        rst = 0b00000100

        count = 0

        flags = self._get_flags()
        for curr_flag in flags:

            #returns true if the bits that are in common
            #are the same as fin
            if ((curr_flag & rst) == rst):
                count += 1 

        return count 

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

        psh = 0b00001000

        count = 0

        flags = self._get_flags()
        for curr_flag in flags:

            #returns true if the bits that are in common
            #are the same as fin
            if ((curr_flag & psh) == psh):
                count += 1 

        return count 


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

        ack = 0b00010000

        count = 0

        flags = self._get_flags()
        for curr_flag in flags:

            #returns true if the bits that are in common
            #are the same as fin
            if ((curr_flag & ack) == ack):
                count += 1 

        return count 


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

        urg = 0b00100000

        count = 0

        flags = self._get_flags()
        for curr_flag in flags:

            #returns true if the bits that are in common
            #are the same as fin
            if ((curr_flag & urg) == urg):
                count += 1 

        return count 


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

        ece = 0b01000000

        count = 0

        flags = self._get_flags()
        for curr_flag in flags:

            #returns true if the bits that are in common
            #are the same as fin
            if ((curr_flag & ece) == ece):
                count += 1 

        return count 


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

        cwr = 0b10000000

        count = 0

        flags = self._get_flags()
        for curr_flag in flags:

            #returns true if the bits that are in common
            #are the same as fin
            if ((curr_flag & cwr) == cwr):
                count += 1 

        return count 


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
        pa = 0x03
        count = self._get_flags().count(pa)

        return count

    def get_synack_count(self) -> int:
        """This feature counts the number of SYN/ACK flags in a flow.

        Returns:
            int: The SYN/ACK flag count

        """
        sa = 0x12
        count = self._get_flags().count(sa)

        return count

    def get_rstack_count(self) -> int:
        """This feature counts the number of RST ACK flags in a flow.

        Returns:
            int: The RST ACK flag count

        """
        ra = 0x14
        count = self._get_flags().count(ra)

        return count

    def get_pshack_count(self) -> int:
        """This feature counts the number of Push ACK flags in a flow.

        Returns:
            int: The Push ACK flag count

        """
        pa = 0x18
        count = self._get_flags().count(pa)

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
        count = 0

        synfin = 0b00000011

        #Assigning the current flag to a variable
        flags = self._get_flags()
        for curr_flag in flags:

            #returns true if the bits that are in common
            #are the same as synfin
            if ((synfin & curr_flag) == synfin):
                count += 1 

        return count    
