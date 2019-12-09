import cryptography

from scapy.layers import tls
from scapy.all import * 


load_layer('tls')
class TlsInfo:
    """
    This class extracts the features related to TLS

    """
    def __init__(self, feature):
        self.feature = feature

    #TODO: Add documentation to functions
    #Functions for getting information within various TLS fields
    def app_data(self):
        return self._tls_packet_loop().get('app_data')

    def alpn(self):
        return self._tls_packet_loop().get('alpn')

    def client_authz(self):
        return self._tls_packet_loop().get('client_authz')

    def client_cert_type(self):
        return self._tls_packet_loop().get('client_certificate_type')

    def client_cert_url(self):
        return self._tls_packet_loop().get('client_certificate_url')     

    def client_cipher_suit(self):
        return self._tls_packet_loop().get('client_cipher_suit')

    def client_hello_msglen(self):
        return self._tls_packet_loop().get('client_hello_msglen')

    def cookie(self):
        return self._tls_packet_loop().get('cookie')

    def compression(self):
        return self._tls_packet_loop().get('compr')

    def csr(self):
        return self._tls_packet_loop().get('csr')

    def early_data(self):
        return self._tls_packet_loop().get('early_data')

    def early_data_ind(self):
        return self._tls_packet_loop().get('early_data_ind')

    def early_data_ind_ticket(self):
        return self._tls_packet_loop().get('early_data_ind_ticket')

    def encrypt_then_mac(self):
        return self._tls_packet_loop().get('encrypt_then_mac')

    def heartbeat(self):
        return self._tls_packet_loop().get('heartbeat')

    def keyshare(self):
        return self._tls_packet_loop().get('keyshare')

    def keyshare_ch(self):
        return self._tls_packet_loop().get('keyshare_ch')

    def keyshare_sh(self):
        return self._tls_packet_loop().get('keyshare_sh')

    def master_secret(self):
        return self._tls_packet_loop().get('master_secret')

    def max_frag(self):
        return self._tls_packet_loop().get('max_frag')

    def ocsp(self):
        return self._tls_packet_loop().get('ocsp')

    def padding(self):
        return self._tls_packet_loop().get('padding')

    def post_handshake_auth(self):
        return self._tls_packet_loop().get('post_handshake_auth')

    def pre_shared_key(self):
        return self._tls_packet_loop().get('pre_shared_key')

    def psk_key_exch(self):
        return self._tls_packet_loop().get('psk_key_exch')

    def record_size_limit(self):
        return self._tls_packet_loop().get('record_size_limit')

    def renogotiation(self):
        return self._tls_packet_loop().get('renegotiation')

    def server_authz(self):
        return self._tls_packet_loop().get('server_authz')

    def server_cert_type(self):
        return self._tls_packet_loop().get('server_certificate_type')

    def server_cipher_suit(self):
        return self._tls_packet_loop().get('server_cipher_suit')

    def server_hello_msglen(self):
        return self._tls_packet_loop().get('server_hello_msglen')

    def server_name(self):
        return self._tls_packet_loop().get('server_name')

    def session_ticket(self):
        return self._tls_packet_loop().get('session_ticket')

    def session_lifetime(self):
        return self._tls_packet_loop().get('lifetime')

    def signature_algorithm(self):
        return self._tls_packet_loop().get('signature_algorithms')

    def signature_algorithm_cert(self):
        return self._tls_packet_loop().get('signature_algorithms_cert')
 
    def sup_groups(self):
        return self._tls_packet_loop().get('supported_groups')

    def supported_elip(self):
        return self._tls_packet_loop().get('supported_elliptic')

    def supported_point_format(self):
        return self._tls_packet_loop().get('supported_point_format')

    def supported_version(self):
        return self._tls_packet_loop().get('supported_version')

    def supported_version_ch(self):
        return self._tls_packet_loop().get('supported_version_ch')

    def supported_version_sh(self):
        return self._tls_packet_loop().get('supported_version_sh')

    def ticket_early_data_info(self):
        return self._tls_packet_loop().get('early_data_ticket')

    def tls_alert(self):
        return self._tls_packet_loop().get('tls_alert')

    def truncated_hmac(self):
        return self._tls_packet_loop().get('truncated_hmac')

    def trusted_ca(self):
        return self._tls_packet_loop().get('trusted_ca')

    def user_mapping(self):
        return self._tls_packet_loop().get('user_mapping')

    #TODO: Expand function out so there is only one loop
    #in this class. Rename function appropriately has helper function
    #Have other functions call to specific values in the main loop function
    #for clarity.
    def _tls_packet_loop(self):
        feat = self.feature
        packets = feat.packets

        #0 meaning we haven't seen this extension

        client_cipher_suit = []
        server_cipher_suit = 0
        client_hello_msglen = 0
        server_hello_msglen = 0
        
        compr = 0
        lifetime = 0

        alpn = 0
        app_data = 0
        client_authz = 0
        client_certificate_type = 0
        client_certificate_url = 0
        cookie = 0
        csr = 0
        early_data = 0
        early_data_ind = 0
        early_data_ind_ticket = 0
        early_data_ticket = 0
        encrypt_then_mac = 0
        heartbeat = 0
        keyshare = 0
        keyshare_ch = 0
        keyshare_sh = 0
        master_secret = 0
        max_frag = 0
        ocsp = 0
        padding = 0
        post_handshake_auth = 0
        pre_shared_key = 0
        psk_key_exch = 0
        record_size_limit = 0
        renegotiation = 0
        server_authz = 0
        server_name = 0
        server_certificate_type = 0
        session_ticket = 0
        signature_algorithms = 0
        signature_algorithms_cert = 0
        supported_elliptic = 0
        supported_groups = 0
        supported_point_format = 0
        supported_version = 0
        supported_version_ch = 0
        supported_version_sh = 0
        ticket_early_data_info = 0
        tls_alert = 0
        truncated_hmac = 0
        trusted_ca = 0
        user_mapping = 0

        #Doing a bunch of loops is too inefficient
        for packet, _ in packets:
            if TLS in packet:
                #1 meaning it has been seen

                if packet['TLS'].type == 22:
                    if TLSServerHello in packet:
                        server_cipher_suit = self._cipher_dict().get(packet[TLSServerHello].cipher)
                        server_hello_msglen = packet[TLSServerHello].msglen

                    if TLSClientHello in packet:
                        client_cipher_suit.append([cipher if self._cipher_dict().get(cipher) \
                        is None else self._cipher_dict().get(cipher) \
                        for cipher in packet[TLSClientHello].ciphers])
                        client_hello_msglen = packet[TLSClientHello].msglen

                    if TLSNewSessionTicket in packet:
                        lifetime = packet[TLSNewSessionTicket].lifetime

                if TLS_Ext_ALPN in packet:
                    alpn = 1

                if TLSApplicationData in packet:
                    app_data = 1

                if TLS_Ext_ClientAuthz in packet:
                    client_authz = 1

                if TLS_Ext_ClientCertType in packet:
                    client_certificate_type = 1

                if TLS_Ext_ClientCertURL in packet:
                    client_certificate_url = 1

                if TLS_Ext_Cookie in packet:
                    cookie = 1

                if TLS_Ext_CSR in packet:
                    csr = 1

                if TLS_Ext_EarlyDataIndication in packet:
                    early_data = 1

                if TLS_Ext_EarlyDataIndicationTicket in packet:
                    early_data_ticket = 1

                if TLS_Ext_EncryptThenMAC in packet:
                    encrypt_then_mac = 1

                if TLS_Ext_ExtendedMasterSecret in packet:
                    master_secret = 1

                if TLS_Ext_Heartbeat in packet:
                    heartbeat = 1

                if TLS_Ext_SessionTicket in packet:
                    session_ticket = 1
                    compr =  [self._ec_point().get(comp) for comp \
                    in packet[TLS_Ext_SupportedPointFormat].ecpl]

                if TLS_Ext_KeyShare in packet:
                    keyshare = 1

                if TLS_Ext_KeyShare_CH in packet:
                    keyshare_ch = 1

                if TLS_Ext_KeyShare_SH in packet:
                    keyshare_sh = 1

                if TLS_Ext_MaxFragLen in packet:
                   max_frag = 1

                if OCSPStatusRequest in packet:
                    ocsp = 1

                if TLS_Ext_Padding in packet:
                    padding = 1

                if TLS_Ext_PostHandshakeAuth in packet:
                    post_handshake_auth = 1

                if TLS_Ext_PreSharedKey in packet:
                    pre_shared_key = 1

                if TLS_Ext_PSKKeyExchangeModes in packet:
                    psk_key_exch = 1

                if TLS_Ext_RecordSizeLimit in packet:
                    record_size_limit = 1

                if TLS_Ext_RenegotiationInfo in packet:
                    renegotiation = 1

                if TLS_Ext_ServerCertType in packet:
                    server_certificate_type = 1

                if TLS_Ext_ServerName in packet:
                    server_name = 1

                if TLS_Ext_ServerAuthz in packet:
                    server_authz = 1

                if TLS_Ext_SignatureAlgorithms in packet:
                    signature_algorithms = 1

                if TLS_Ext_SignatureAlgorithmsCert in packet:
                    signature_algorithms_cert = 1

                if TLS_Ext_SupportedEllipticCurves in packet:
                    supported_elliptic = 1

                if TLS_Ext_SupportedGroups in packet:
                    supported_groups = 1

                if TLS_Ext_SupportedPointFormat in packet:
                    supported_point_format = 1

                if TLS_Ext_SupportedVersions in packet:
                    supported_version = 1

                if TLS_Ext_SupportedVersion_CH in packet:
                    supported_version_ch = 1

                if TLS_Ext_SupportedVersion_SH in packet:
                    supported_version_sh = 1

                if TLS_Ext_TicketEarlyDataInfo in packet:
                    ticket_early_data_info = 1

                if TLSAlert in packet:
                    tls_alert = 1

                if TLS_Ext_TruncatedHMAC in packet:
                    truncated_hmac = 1

                if TLS_Ext_TrustedCAInd in packet:
                    trusted_ca = 1

                if TLS_Ext_UserMapping in packet:
                    user_mapping = 1

        return  {

            'client_cipher_suit' : client_cipher_suit,
            'server_cipher_suit' : server_cipher_suit,
            'client_hello_msglen' : client_hello_msglen,
            'server_hello_msglen' : server_hello_msglen,

            'compr' : compr,
            'lifetime' : lifetime,

            'alpn' : alpn, #application_layer_protocol_negotiation
            'app_data' : app_data, 
            'csr' : csr,
            'client_authz' : client_authz,
            'client_certificate_type' : client_certificate_type,
            'client_certificate_url' : client_certificate_url,
            'cookie' : cookie,
            'early_data' : early_data,
            'early_data_ind' : early_data_ind,
            'early_data_ind_ticket' : early_data_ind_ticket,
            'early_data_ticket' : early_data_ticket,
            'encrypt_then_mac' : encrypt_then_mac,
            'heartbeat' : heartbeat,
            'keyshare' : keyshare,
            'keyshare_ch' : keyshare_ch, 
            'keyshare_sh' : keyshare_sh,
            'master_secret' : master_secret,
            'max_frag' : max_frag,
            'ocsp' : ocsp,
            'padding' : padding,
            'post_handshake_auth' : post_handshake_auth,
            'pre_shared_key' : pre_shared_key,
            'psk_key_exch' : psk_key_exch,
            'record_size_limit' : record_size_limit, 
            'renegotiation' : renegotiation,
            'server_certificate_type' : server_certificate_type,
            'server_name' : server_name,
            'server_authz' : server_authz,
            'session_ticket' : session_ticket,
            'signature_algorithms' : signature_algorithms,
            'signature_algorithms_cert' : signature_algorithms_cert,
            'supported_elliptic' : supported_elliptic, 
            'supported_groups' : supported_groups,
            'supported_point_format' : supported_point_format,
            'supported_version' : supported_version,
            'supported_version_ch' : supported_version_ch,
            'supported_version_sh' : supported_version_sh,
            'ticket_early_data_info' : ticket_early_data_info, 
            'tls_alert' : tls_alert,
            'truncated_hmac' : truncated_hmac,
            'trusted_ca' : trusted_ca,
            'user_mapping' : user_mapping,
        }

    def _cipher_dict(self):
        """Hexidecimal values of cipher suites
        with their corresponding string names.

        Notes:
            Main Source https://testssl.sh/openssl-iana.mapping.html
            and scapy

        """
        cipher_dict = {
            0x0000 : 'NULL_WITH_NULL_NULL',
            0x0001 : 'RSA_WITH_NULL_MD5',
            0x0002 : 'RSA_WITH_NULL_SHA',
            0x0003 : 'RSA_EXPORT_WITH_RC4_40_MD5',
            0x0004 : 'RSA_WITH_RC4_128_MD5',
            0x0005 : 'RSA_WITH_RC4_128_SHA',
            0x0006 : 'RSA_EXPORT_WITH_RC2_CBC_40_MD5',
            0x0007 : 'RSA_WITH_IDEA_CBC_SHA',
            0x0008 : 'RSA_EXPORT_WITH_DES40_CBC_SHA',
            0x0009 : 'RSA_WITH_DES_CBC_SHA',
            0x000a : 'RSA_WITH_3DES_EDE_CBC_SHA',
            0x000b : 'DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
            0x000c : 'DH_DSS_WITH_DES_CBC_SHA',
            0x000d : 'DH_DSS_WITH_3DES_EDE_CBC_SHA',
            0x000e : 'DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
            0x000f : 'DH_RSA_WITH_DES_CBC_SHA',
            0x0010 : 'DH_RSA_WITH_3DES_EDE_CBC_SHA',
            0x0011 : 'DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
            0x0012 : 'DHE_DSS_WITH_DES_CBC_SHA',
            0x0013 : 'DHE_DSS_WITH_3DES_EDE_CBC_SHA',
            0x0014 : 'DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
            0x0015 : 'DHE_RSA_WITH_DES_CBC_SHA',
            0x0016 : 'DHE_RSA_WITH_3DES_EDE_CBC_SHA',
            0x0017 : 'DH_anon_EXPORT_WITH_RC4_40_MD5',
            0x0018 : 'DH_anon_WITH_RC4_128_MD5',
            0x0019 : 'DH_anon_EXPORT_WITH_DES40_CBC_SHA',
            0x001a : 'DH_anon_WITH_DES_CBC_SHA',
            0x001b : 'DH_anon_WITH_3DES_EDE_CBC_SHA',
            0x001c : 'SSL_FORTEZZA_KEA_WITH_NULL_SHA',
            0x001d : 'SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA',
            0x001e : 'KRB5_WITH_DES_CBC_SHA',
            0x001f : 'KRB5_WITH_3DES_EDE_CBC_SHA',
            0x0020 : 'KRB5_WITH_RC4_128_SHA',
            0x0021 : 'KRB5_WITH_IDEA_CBC_SHA',
            0x0022 : 'KRB5_WITH_DES_CBC_MD5',
            0x0023 : 'KRB5_WITH_3DES_EDE_CBC_MD5',
            0x0024 : 'KRB5_WITH_RC4_128_MD5',
            0x0025 : 'KRB5_WITH_IDEA_CBC_MD5',
            0x0026 : 'KRB5_EXPORT_WITH_DES_CBC_40_SHA',
            0x0027 : 'KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
            0x0028 : 'KRB5_EXPORT_WITH_RC4_40_SHA',
            0x0029 : 'KRB5_EXPORT_WITH_DES_CBC_40_MD5',
            0x002a : 'KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
            0x002b : 'KRB5_EXPORT_WITH_RC4_40_MD5',
            0x002c : 'PSK_WITH_NULL_SHA',
            0x002d : 'DHE_PSK_WITH_NULL_SHA',
            0x002e : 'RSA_PSK_WITH_NULL_SHA',
            0x002f : 'RSA_WITH_AES_128_CBC_SHA',
            0x0030 : 'DH_DSS_WITH_AES_128_CBC_SHA',
            0x0031 : 'DH_RSA_WITH_AES_128_CBC_SHA',
            0x0032 : 'DHE_DSS_WITH_AES_128_CBC_SHA',
            0x0033 : 'DHE_RSA_WITH_AES_128_CBC_SHA',
            0x0034 : 'DH_anon_WITH_AES_128_CBC_SHA',
            0x0035 : 'RSA_WITH_AES_256_CBC_SHA',
            0x0036 : 'DH_DSS_WITH_AES_256_CBC_SHA',
            0x0037 : 'DH_RSA_WITH_AES_256_CBC_SHA',
            0x0038 : 'DHE_DSS_WITH_AES_256_CBC_SHA',
            0x0039 : 'DHE_RSA_WITH_AES_256_CBC_SHA',
            0x003a : 'DH_anon_WITH_AES_256_CBC_SHA',
            0x003b : 'RSA_WITH_NULL_SHA256',
            0x003c : 'RSA_WITH_AES_128_CBC_SHA256',
            0x003d : 'RSA_WITH_AES_256_CBC_SHA256',
            0x003e : 'DH_DSS_WITH_AES_128_CBC_SHA256',
            0x003f : 'DH_RSA_WITH_AES_128_CBC_SHA256',
            0x0040 : 'DHE_DSS_WITH_AES_128_CBC_SHA256',
            0x0041 : 'RSA_WITH_CAMELLIA_128_CBC_SHA',
            0x0042 : 'DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
            0x0043 : 'DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
            0x0044 : 'DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
            0x0045 : 'DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
            0x0046 : 'DH_anon_WITH_CAMELLIA_128_CBC_SHA',
            0x0060 : 'TLS_RSA_EXPORT1024_WITH_RC4_56_MD5',
            0x0061 : 'TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5',
            0x0062 : 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA',
            0x0063 : 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
            0x0064 : 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA',
            0x0065 : 'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',
            0x0066 : 'TLS_DHE_DSS_WITH_RC4_128_SHA',
            0x0067 : 'DHE_RSA_WITH_AES_128_CBC_SHA256',
            0x0068 : 'DH_DSS_WITH_AES_256_CBC_SHA256',
            0x0069 : 'DH_RSA_WITH_AES_256_CBC_SHA256',
            0x006a : 'DHE_DSS_WITH_AES_256_CBC_SHA256',
            0x006b : 'DHE_RSA_WITH_AES_256_CBC_SHA256',
            0x006c : 'DH_anon_WITH_AES_128_CBC_SHA256',
            0x006d : 'DH_anon_WITH_AES_256_CBC_SHA256',
            0x0080 : 'TLS_GOSTR341094_WITH_28147_CNT_IMIT',
            0x0081 : 'TLS_GOSTR341001_WITH_28147_CNT_IMIT',
            0x0082 : 'TLS_GOSTR341001_WITH_NULL_GOSTR3411',
            0x0083 : 'TLS_GOSTR341094_WITH_NULL_GOSTR3411',
            0x0084 : 'RSA_WITH_CAMELLIA_256_CBC_SHA',
            0x0085 : 'DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
            0x0086 : 'DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
            0x0087 : 'DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
            0x0088 : 'DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
            0x0089 : 'DH_anon_WITH_CAMELLIA_256_CBC_SHA',
            0x008a : 'PSK_WITH_RC4_128_SHA',
            0x008b : 'PSK_WITH_3DES_EDE_CBC_SHA',
            0x008c : 'PSK_WITH_AES_128_CBC_SHA',
            0x008d : 'PSK_WITH_AES_256_CBC_SHA',
            0x008e : 'DHE_PSK_WITH_RC4_128_SHA',
            0x008f : 'DHE_PSK_WITH_3DES_EDE_CBC_SHA',
            0x0090 : 'DHE_PSK_WITH_AES_128_CBC_SHA',
            0x0091 : 'DHE_PSK_WITH_AES_256_CBC_SHA',
            0x0092 : 'RSA_PSK_WITH_RC4_128_SHA',
            0x0093 : 'RSA_PSK_WITH_3DES_EDE_CBC_SHA',
            0x0094 : 'RSA_PSK_WITH_AES_128_CBC_SHA',
            0x0095 : 'RSA_PSK_WITH_AES_256_CBC_SHA',
            0x0096 : 'RSA_WITH_SEED_CBC_SHA',
            0x0097 : 'DH_DSS_WITH_SEED_CBC_SHA',
            0x0098 : 'DH_RSA_WITH_SEED_CBC_SHA',
            0x0099 : 'DHE_DSS_WITH_SEED_CBC_SHA',
            0x009a : 'DHE_RSA_WITH_SEED_CBC_SHA',
            0x009b : 'DH_anon_WITH_SEED_CBC_SHA',
            0x009c : 'RSA_WITH_AES_128_GCM_SHA256',
            0x009d : 'RSA_WITH_AES_256_GCM_SHA384',
            0x009e : 'DHE_RSA_WITH_AES_128_GCM_SHA256',
            0x009f : 'DHE_RSA_WITH_AES_256_GCM_SHA384',
            0x00a0 : 'DH_RSA_WITH_AES_128_GCM_SHA256',
            0x00a1 : 'DH_RSA_WITH_AES_256_GCM_SHA384',
            0x00a2 : 'DHE_DSS_WITH_AES_128_GCM_SHA256',
            0x00a3 : 'DHE_DSS_WITH_AES_256_GCM_SHA384',
            0x00a4 : 'DH_DSS_WITH_AES_128_GCM_SHA256',
            0x00a5 : 'DH_DSS_WITH_AES_256_GCM_SHA384',
            0x00a6 : 'DH_anon_WITH_AES_128_GCM_SHA256',
            0x00a7 : 'DH_anon_WITH_AES_256_GCM_SHA384',
            0x00a8 : 'PSK_WITH_AES_128_GCM_SHA256',
            0x00a9 : 'PSK_WITH_AES_256_GCM_SHA384',
            0x00aa : 'DHE_PSK_WITH_AES_128_GCM_SHA256',
            0x00ab : 'DHE_PSK_WITH_AES_256_GCM_SHA384',
            0x00ac : 'RSA_PSK_WITH_AES_128_GCM_SHA256',
            0x00ad : 'RSA_PSK_WITH_AES_256_GCM_SHA384',
            0x00ae : 'PSK_WITH_AES_128_CBC_SHA256',
            0x00af : 'PSK_WITH_AES_256_CBC_SHA384',
            0x00b0 : 'PSK_WITH_NULL_SHA256',
            0x00b1 : 'PSK_WITH_NULL_SHA384',
            0x00b2 : 'DHE_PSK_WITH_AES_128_CBC_SHA256',
            0x00b3 : 'DHE_PSK_WITH_AES_256_CBC_SHA384',
            0x00b4 : 'DHE_PSK_WITH_NULL_SHA256',
            0x00b5 : 'DHE_PSK_WITH_NULL_SHA384',
            0x00b6 : 'RSA_PSK_WITH_AES_128_CBC_SHA256',
            0x00b7 : 'RSA_PSK_WITH_AES_256_CBC_SHA384',
            0x00b8 : 'RSA_PSK_WITH_NULL_SHA256',
            0x00b9 : 'RSA_PSK_WITH_NULL_SHA384',
            0x00ba : 'RSA_WITH_CAMELLIA_128_CBC_SHA256',
            0x00bb : 'DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
            0x00bc : 'DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
            0x00bd : 'DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
            0x00be : 'DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
            0x00bf : 'DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
            0x00c0 : 'RSA_WITH_CAMELLIA_256_CBC_SHA256',
            0x00c1 : 'DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
            0x00c2 : 'DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
            0x00c3 : 'DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
            0x00c4 : 'DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
            0x00c5 : 'DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
            0x00ff : 'EMPTY_RENEGOTIATIOn_SCSV',
            0x5600 : 'FALLBACK_SCSV',
            0x1301 : 'TLS_AES_128_GCM_SHA256',
            0x1302 : 'TLS_AES_256_GCM_SHA384',
            0x1303 : 'TLS_CHACHA20_POLY1305_SHA256',
            0x1304 : 'TLS_AES_128_CCM_SHA256',
            0x1305 : 'TLS_AES_128_CCM_8_SHA256',
            0xc001 : 'ECDH_ECDSA_WITH_NULL_SHA',
            0xc002 : 'ECDH_ECDSA_WITH_RC4_128_SHA',
            0xc003 : 'ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
            0xc004 : 'ECDH_ECDSA_WITH_AES_128_CBC_SHA',
            0xc005 : 'ECDH_ECDSA_WITH_AES_256_CBC_SHA',
            0xc006 : 'ECDHE_ECDSA_WITH_NULL_SHA',
            0xc007 : 'ECDHE_ECDSA_WITH_RC4_128_SHA',
            0xc008 : 'ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
            0xc009 : 'ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
            0xc00a : 'ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
            0xc00b : 'ECDH_RSA_WITH_NULL_SHA',
            0xc00c : 'ECDH_RSA_WITH_RC4_128_SHA',
            0xc00d : 'ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
            0xc00e : 'ECDH_RSA_WITH_AES_128_CBC_SHA',
            0xc00f : 'ECDH_RSA_WITH_AES_256_CBC_SHA',
            0xc010 : 'ECDHE_RSA_WITH_NULL_SHA',
            0xc011 : 'ECDHE_RSA_WITH_RC4_128_SHA',
            0xc012 : 'ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
            0xc013 : 'ECDHE_RSA_WITH_AES_128_CBC_SHA',
            0xc014 : 'ECDHE_RSA_WITH_AES_256_CBC_SHA',
            0xc015 : 'ECDH_anon_WITH_NULL_SHA',
            0xc016 : 'ECDH_anon_WITH_RC4_128_SHA',
            0xc017 : 'ECDH_anon_WITH_3DES_EDE_CBC_SHA',
            0xc018 : 'ECDH_anon_WITH_AES_128_CBC_SHA',
            0xc019 : 'ECDH_anon_WITH_AES_256_CBC_SHA',
            0xc01a : 'SRP_SHA_WITH_3DES_EDE_CBC_SHA',
            0xc01b : 'SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
            0xc01c : 'SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
            0xc01d : 'SRP_SHA_WITH_AES_128_CBC_SHA',
            0xc01e : 'SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
            0xc01f : 'SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
            0xc020 : 'SRP_SHA_WITH_AES_256_CBC_SHA',
            0xc021 : 'SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
            0xc022 : 'SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
            0xc023 : 'ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
            0xc024 : 'ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
            0xc025 : 'ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
            0xc026 : 'ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
            0xc027 : 'ECDHE_RSA_WITH_AES_128_CBC_SHA256',
            0xc028 : 'ECDHE_RSA_WITH_AES_256_CBC_SHA384',
            0xc029 : 'ECDH_RSA_WITH_AES_128_CBC_SHA256',
            0xc02a : 'ECDH_RSA_WITH_AES_256_CBC_SHA384',
            0xc02b : 'ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            0xc02c : 'ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            0xc02d : 'ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
            0xc02e : 'ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
            0xc02f : 'ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            0xc030 : 'ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            0xc031 : 'ECDH_RSA_WITH_AES_128_GCM_SHA256',
            0xc032 : 'ECDH_RSA_WITH_AES_256_GCM_SHA384',
            0xc033 : 'ECDHE_PSK_WITH_RC4_128_SHA',
            0xc034 : 'ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
            0xc035 : 'ECDHE_PSK_WITH_AES_128_CBC_SHA',
            0xc036 : 'ECDHE_PSK_WITH_AES_256_CBC_SHA',
            0xc037 : 'ECDHE_PSK_WITH_AES_128_CBC_SHA256',
            0xc038 : 'ECDHE_PSK_WITH_AES_256_CBC_SHA384',
            0xc039 : 'ECDHE_PSK_WITH_NULL_SHA',
            0xc03a : 'ECDHE_PSK_WITH_NULL_SHA256',
            0xc03b : 'ECDHE_PSK_WITH_NULL_SHA384',
            0xc03c : 'RSA_WITH_ARIA_128_CBC_SHA256',
            0xc03d : 'RSA_WITH_ARIA_256_CBC_SHA384',
            0xc03e : 'DH_DSS_WITH_ARIA_128_CBC_SHA256',
            0xc03f : 'DH_DSS_WITH_ARIA_256_CBC_SHA384',
            0xc040 : 'DH_RSA_WITH_ARIA_128_CBC_SHA256',
            0xc041 : 'DH_RSA_WITH_ARIA_256_CBC_SHA384',
            0xc042 : 'DHE_DSS_WITH_ARIA_128_CBC_SHA256',
            0xc043 : 'DHE_DSS_WITH_ARIA_256_CBC_SHA384',
            0xc044 : 'DHE_RSA_WITH_ARIA_128_CBC_SHA256',
            0xc045 : 'DHE_RSA_WITH_ARIA_256_CBC_SHA384',
            0xc046 : 'DH_anon_WITH_ARIA_128_CBC_SHA256',
            0xc047 : 'DH_anon_WITH_ARIA_256_CBC_SHA384',
            0xc048 : 'ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
            0xc049 : 'ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
            0xc04a : 'ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256',
            0xc04b : 'ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384',
            0xc04c : 'ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
            0xc04d : 'ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
            0xc04e : 'ECDH_RSA_WITH_ARIA_128_CBC_SHA256',
            0xc04f : 'ECDH_RSA_WITH_ARIA_256_CBC_SHA384',
            0xc050 : 'RSA_WITH_ARIA_128_GCM_SHA256',
            0xc051 : 'RSA_WITH_ARIA_256_GCM_SHA384',
            0xc052 : 'DHE_RSA_WITH_ARIA_128_GCM_SHA256',
            0xc053 : 'DHE_RSA_WITH_ARIA_256_GCM_SHA384',
            0xc054 : 'DH_RSA_WITH_ARIA_128_GCM_SHA256',
            0xc055 : 'DH_RSA_WITH_ARIA_256_GCM_SHA384',
            0xc056 : 'DHE_DSS_WITH_ARIA_128_GCM_SHA256',
            0xc057 : 'DHE_DSS_WITH_ARIA_256_GCM_SHA384',
            0xc058 : 'DH_DSS_WITH_ARIA_128_GCM_SHA256',
            0xc059 : 'DH_DSS_WITH_ARIA_256_GCM_SHA384',
            0xc05a : 'DH_anon_WITH_ARIA_128_GCM_SHA256',
            0xc05b : 'DH_anon_WITH_ARIA_256_GCM_SHA384',
            0xc05c : 'ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
            0xc05d : 'ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
            0xc05e : 'ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256',
            0xc05f : 'ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384',
            0xc060 : 'ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
            0xc061 : 'ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
            0xc062 : 'ECDH_RSA_WITH_ARIA_128_GCM_SHA256',
            0xc063 : 'ECDH_RSA_WITH_ARIA_256_GCM_SHA384',
            0xc064 : 'PSK_WITH_ARIA_128_CBC_SHA256',
            0xc065 : 'PSK_WITH_ARIA_256_CBC_SHA384',
            0xc066 : 'DHE_PSK_WITH_ARIA_128_CBC_SHA256',
            0xc067 : 'DHE_PSK_WITH_ARIA_256_CBC_SHA384',
            0xc068 : 'RSA_PSK_WITH_ARIA_128_CBC_SHA256',
            0xc069 : 'RSA_PSK_WITH_ARIA_256_CBC_SHA384',
            0xc06a : 'PSK_WITH_ARIA_128_GCM_SHA256',
            0xc06b : 'PSK_WITH_ARIA_256_GCM_SHA384',
            0xc06c : 'DHE_PSK_WITH_ARIA_128_GCM_SHA256',
            0xc06d : 'DHE_PSK_WITH_ARIA_256_GCM_SHA384',
            0xc06e : 'RSA_PSK_WITH_ARIA_128_GCM_SHA256',
            0xc06f : 'RSA_PSK_WITH_ARIA_256_GCM_SHA384',
            0xc070 : 'ECDHE_PSK_WITH_ARIA_128_CBC_SHA256',
            0xc071 : 'ECDHE_PSK_WITH_ARIA_256_CBC_SHA384',
            0xc072 : 'ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
            0xc073 : 'ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
            0xc074 : 'ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
            0xc075 : 'ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
            0xc076 : 'ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
            0xc077 : 'ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
            0xc078 : 'ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
            0xc079 : 'ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
            0xc07a : 'RSA_WITH_CAMELLIA_128_GCM_SHA256',
            0xc07b : 'RSA_WITH_CAMELLIA_256_GCM_SHA384',
            0xc07c : 'DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
            0xc07d : 'DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
            0xc07e : 'DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
            0xc07f : 'DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
            0xc080 : 'DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
            0xc081 : 'DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
            0xc082 : 'DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
            0xc083 : 'DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
            0xc084 : 'DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
            0xc085 : 'DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
            0xc086 : 'ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
            0xc087 : 'ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
            0xc088 : 'ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
            0xc089 : 'ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
            0xc08a : 'ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
            0xc08b : 'ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
            0xc08c : 'ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
            0xc08d : 'ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
            0xc08e : 'PSK_WITH_CAMELLIA_128_GCM_SHA256',
            0xc08f : 'PSK_WITH_CAMELLIA_256_GCM_SHA384',
            0xc090 : 'DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
            0xc091 : 'DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
            0xc092 : 'RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
            0xc093 : 'RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
            0xc094 : 'PSK_WITH_CAMELLIA_128_CBC_SHA256',
            0xc095 : 'PSK_WITH_CAMELLIA_256_CBC_SHA384',
            0xc096 : 'DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
            0xc097 : 'DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
            0xc098 : 'RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
            0xc099 : 'RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
            0xc09a : 'ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
            0xc09b : 'ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
            0xc09c : 'RSA_WITH_AES_128_CCM',
            0xc09d : 'RSA_WITH_AES_256_CCM',
            0xc09e : 'DHE_RSA_WITH_AES_128_CCM',
            0xc09f : 'DHE_RSA_WITH_AES_256_CCM',
            0xc0a0 : 'RSA_WITH_AES_128_CCM_8',
            0xc0a1 : 'RSA_WITH_AES_256_CCM_8',
            0xc0a2 : 'DHE_RSA_WITH_AES_128_CCM_8',
            0xc0a3 : 'DHE_RSA_WITH_AES_256_CCM_8',
            0xc0a4 : 'PSK_WITH_AES_128_CCM',
            0xc0a5 : 'PSK_WITH_AES_256_CCM',
            0xc0a6 : 'DHE_PSK_WITH_AES_128_CCM',
            0xc0a7 : 'DHE_PSK_WITH_AES_256_CCM',
            0xc0a8 : 'PSK_WITH_AES_128_CCM_8',
            0xc0a9 : 'PSK_WITH_AES_256_CCM_8',
            0xc0aa : 'PSK_DHE_WITH_AES_128_CCM_8',
            0xc0ab : 'PSK_DHE_WITH_AES_256_CCM_8',
            0xc0ac : 'ECDHE_ECDSA_WITH_AES_128_CCM',
            0xc0ad : 'ECDHE_ECDSA_WITH_AES_256_CCM',
            0xc0ae : 'ECDHE_ECDSA_WITH_AES_128_CCM_8',
            0xc0af : 'ECDHE_ECDSA_WITH_AES_256_CCM_8',
        }
        return cipher_dict

    def _ec_point(self):
        ec_point = {
            0x00: 'uncompressed',
            0x01: 'ansiX962_compressed_prime',
            0x02: 'ansiX962_compressed_char2',
        }
        return ec_point