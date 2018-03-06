# -*- coding: utf-8 -*-
"""
    This module detects Silver Ticket Attack.
    Info about Silver Ticket:
    https://www.cyberark.com/blog/service-accounts-weakest-link-chain/
    https://adsecurity.org/?p=2011

    Silver ticket is an attack that takes place after an attacker compromise a service key / password.
    With that key an attacker can create and send a forged service ticket at ap-req.
    In the service ticket the attacker can change which groups they belong to
    and also can use a none exists username in order to elevate his privileges.

    The attack is detected by verify the privsvr (KRBTGT) signature.
    The privsvr signature is  a checksum of the server signature field encrypted with KRBTGT key.

    Thanks to CoreSecurity Impacket for doing a great job around the crypto and Kerberos.
    https://github.com/CoreSecurity/impacket
    dependencies:impacket

    Author: Hoorvitch Ido (@hoorvitch)
    Copyright: © 2018 CyberArk Software Ltd. All rights reserved
    License: License - NetRay is licensed under the Internal Use License-(https://github.com/cyberark/NetRay/blob/master/LICENSE)
"""

### IMPORTS ###
import impacket.krb5.crypto as crypto
from impacket.krb5.constants import EncryptionTypes, ChecksumTypes, KERB_NON_KERB_CKSUM_SALT

import keytab_parser
from attackdetection import AttackDetection
from utils import *


### Consts ###
# Dictionary key names
# Kerberos protocol element name
SPENGO_KRB_PROTO = 'spnego-krb5'
# Kerberos AP element name
KRB_AP_REQ_KEY_NAME = 'kerberos.ap_req_element'
# Checksum elements names
SERVER_CKSUM_TREE_KEY_NAME = 'kerberos.pac_server_checksum_tree'
KRBTGT_CKSUM_TREE_KEY_NAME = 'kerberos.pac_privsvr_checksum_tree'
CKSUM_SIG_KEY_NAME = 'kerberos.pac.signature.signature'
CKSUM_TYPE_KEY_NAME = 'kerberos.pac.signature.type'
# Sname key name
SNAME_KEY_NAME = 'kerberos.SNameString_dup_0'
# The encryption algorithm for the ap-req
ENC_TYPE_KEY_NAME = 'kerberos.etype'

# Const MSG
# When a packet wasn't decrypted
PARTIAL_KEYTAB_MSG              = "The following packets wasn't checked for Silver Ticket " \
                                   "because the right key wasn't found at the keytab:"
ST_DETECTED_BY_CKSUM_MSG       = 'Silver Ticket was detected by invalid checksum, '\
                                  'The following accounts were compromised :'
KEYS_INFO_MSG                  = 'SPN: {spn}\tKey algorithm:{key_algo}\tPacket numbers:{packet_number}'
BAD_CHKSUM_EXCEPTION           = 'checksum verification failure'
CANT_CHECK_ST_MSG              = 'Silver Ticket attack detection cannot be executed because no KRBTGT ' \
                                 'keys were found at the keytab'
SILVER_TICKET_RESULT_MSG       = 'Silver Ticket attack detection execution finished with the following results:'
LOG_SILVER_TICKET_STRTING_MSG  = "Started Silver Ticket detection."
LOG_SILVER_TICKET_FINISHED_MSG = "Finished Silver Ticket detection."
NO_RESULT_MSG                  = "Silver Ticket detection finished without any findings."

# HMAC does not have enc attribute, we are adding this attribute to it.
ENC_ATTR = 'enc'
# Proxy dictionary that is used in order to fill in KRBTGT keys in KRBTGT_keys_dict from a keytab file.
key_types_proxy = {'arcfour-hmac-md5': crypto._HMACMD5,
                   'aes256-cts-hmac-sha1-96': crypto._SHA1AES256,
                   'aes128-cts-hmac-sha1-96': crypto._SHA1AES128}
# KRBTGT account name
KRBTGT_ACCOUNT_NAME = 'krbtgt'

# dictionary consts for missing keys.
SPN_ELEMENT = 'spn'
KEY_ALGO_ELEMENT = 'key_algo'
PACKETS_ELEMENTS = 'packet_number'

# The format of the module output
WELCOME_OUTPUT_FORMAT = '\t{}'
FINDINGS_OUTPUT_FORMAT = '\n\t\t{}'
KEYS_OUTPUT_SEPARATOR    = '\n\t\t\t'


### Exceptions ###
class SilverTicketDetected(Exception):
    """Raised when Silver Ticket was found"""
    pass

class SilverTicketSkipped(Exception):
    """Raised when a packet wasn't checked for Silver Ticket attack"""
    pass

class FailedParsingKeysError(Exception):
    """Raised when no Krbtgt keys were parsed from the keytab """
    pass

class SilverTicketDetection(AttackDetection):
    """
    Silver Ticket attack detection class.
    """

    # Where to look for protocol type.
    protocol_key_name = PROTO_KEY_NAME
    # Which protocol to look for
    protocol_value = SPENGO_KRB_PROTO
    # Element which if exists indicates that the packet is relevant to the attack.
    identify_keyword = KRB_AP_REQ_KEY_NAME
    # Dictionary that will hold : (key algorithem:key) for KRBTGT account.
    KRBTGT_keys_dict = {}

    @classmethod
    def is_relevant(cls, packet):
        """
        Boolean function which checks if a packet is relevant
        for Silver Ticket attack detection.
        If the packet has Kerberos part and is AP-REQ it needs to be checked.
        :param packet: The packet to check.
        :return: True if the packet is relevant for this attack, False otherwise.
        """
        try:
            # Check whether the packet has KRB part, because it is faster.
            if cls.protocol_value in get_dict_key_value(packet, cls.protocol_key_name):
                # Checking if the packet has AP-REQ part.
                get_dict_key_value(packet, cls.identify_keyword)
                # The packet has everything and should be checked.
                return True

        # The packet is not relevant for this attack and need to be skipped.
        except(KeyNotFoundError):
            pass
        return False


    @classmethod
    def detect(cls, packet_list, parsed_argparse):
        """
        Function which gets KRBTGT keys and send the relevant packets to detection.
        :param packet_list: List which contains all the packets.
        :param opt_args: Optional args , We use it to get the keytab path.
        :return:
        """
        # Write Silver Ticket started.
        write_log(LOG_SILVER_TICKET_STRTING_MSG, 0, write_to_screen=True )

        # Calls the function that fill in KRBTGT keys from a KeyTab.
        cls.extract_keys(parsed_argparse.KeyTabPath)
        # List that will contain keys that was compromised by Silver Ticket attack.
        detected_keys_list = []
        # List of packets that the detection was skipped because the keys are missing.
        skipped_missing_keys_list = []

        # Run over the packet list, the relevant packets will be sent to detection.
        for packet in packet_list:
            # Check if the packet is relevant for Silver Ticket attack detection.
            if not (cls.is_relevant(packet)):
                # The packet is not relevant.
                continue
            # The packet is relevant, sending it to the detection process.
            try:
                # Send the packet to the detection process.
                cls.__detect_by_cksum(packet)
            # If that exception was raised , an attack execution was detected.
            except SilverTicketDetected:
                # Add the packet to the detected list.
                cls.__append_key_info(detected_keys_list, packet)

            # If that exception was raised, the packet was skipped because a key is missing.
            except SilverTicketSkipped:
                cls.__append_key_info(skipped_missing_keys_list, packet)


        execution_output = SILVER_TICKET_RESULT_MSG
        # Writing to log in case Silver Ticket was detected.
        if detected_keys_list:
            execution_output = cls.key_list_output_handling(detected_keys_list,
                                                         ST_DETECTED_BY_CKSUM_MSG,
                                                         execution_output)
        # Writing to log in case packets were skipped from the detection process.
        if skipped_missing_keys_list:
            execution_output = cls.key_list_output_handling(skipped_missing_keys_list,
                                                             PARTIAL_KEYTAB_MSG,
                                                             execution_output)
        # Write to log Silver Ticket ended.
        write_log(LOG_SILVER_TICKET_FINISHED_MSG, 0, write_to_screen = True)
        # If the detection found nothing.
        if not detected_keys_list and not skipped_missing_keys_list:
            # Write to log that nothing was found
            write_log(NO_RESULT_MSG, 1)
            return NO_RESULT_MSG

        # Log the results in case an attack was found or a packet were skipped.
        write_log(execution_output, 1)
        # Return the results in case an attack was found or a packet were skipped.
        return execution_output

    @classmethod
    def key_list_output_handling(cls, keys_info_list, output_title, current_output =''):
        """
        Function that gets a list of keys information and add it to a string.
        :param keys_info_list: List of keys to be added to the output.
        :param output_title: The Title of the result to be printed before.
        :param current_output: The current output of the module.
        :return:
        """
        # Add to current output the result title.
        current_output +=  '\n\t\t' + output_title
        # Add each key to the output.
        for key_info in keys_info_list:
            # Add separator between keys.
            current_output += KEYS_OUTPUT_SEPARATOR
            # Add a key
            current_output += KEYS_INFO_MSG.format(**key_info)
        return current_output


    @classmethod
    def __detect_by_cksum(cls, packet):
        """
        Function which detects Silver Ticket attack execution by wrong privsvr (KRBTGT) checksum.
        We find which algorithm was used and verifying the privsvr signature.
        That is the same idea as using PAC validation, which most of servers don't do.
        We are raising exception if the attack was detected or if a packet wasn't decrypted.
        :param packet: Packet to check in if Silver Ticket attack was executed.
        :return:
        """

        # Get the packet id.
        packet_id = int(get_dict_key_value(packet, FRAME_NUM_KEY_NAME))
        # Get the AP-REQ part of the packet for faster checks in the future.
        apReqDict = get_dict_key_value(packet, cls.identify_keyword)
        try:
            # Getting the PAC checksums
            server_cksum = hex_to_str(get_dict_key_value(apReqDict, SERVER_CKSUM_TREE_KEY_NAME)[CKSUM_SIG_KEY_NAME])
            privsvr_chksum = hex_to_str(get_dict_key_value(apReqDict, KRBTGT_CKSUM_TREE_KEY_NAME)[CKSUM_SIG_KEY_NAME])
            cksum_type_number = get_dict_key_value(apReqDict, KRBTGT_CKSUM_TREE_KEY_NAME)[CKSUM_TYPE_KEY_NAME]

        # The encrypted part wasn't decrypted because the right key is missing.
        except KeyNotFoundError:
            raise SilverTicketSkipped()

        # Get the checksum algorithm.
        cksum_algo = crypto._get_checksum_profile(int(cksum_type_number))
        # Get the KRBTGT key of the the specific algorithm.
        KRBTGT_key = hex_to_str(cls.KRBTGT_keys_dict[cksum_algo])
        # -138 == HMAC doesnt have key algorithm.
        if (not hasattr(cksum_algo, ENC_ATTR)) and (crypto._HMACMD5 == cksum_algo):
            # We are adding key algorithm attribute.
            cksum_algo.enc = crypto._RC4
        # Create a key from the Krbtgt key type and string.
        KRBTGT_key = crypto.Key(cksum_algo.enc.enctype, KRBTGT_key)

        # Validating if the signature is valid, if not an attack was executed.
        try:
            # Verifying the packet checksum with the real KRBTGT key.
            # If the verify failed , exception will be raised.
            cksum_algo.verify(KRBTGT_key,
                            KERB_NON_KERB_CKSUM_SALT,
                            server_cksum,
                            privsvr_chksum
                            )

        # Wrong signature found
        except crypto.InvalidChecksum as expt:
            if expt.message in BAD_CHKSUM_EXCEPTION:
                # The signature is wrong, Silver Ticket attack execution was detected!.
                raise SilverTicketDetected()

            # Unknown exception
            raise expt

            # If we got here the checksums were legit.

    @classmethod
    def extract_keys(cls, keytab_path):
        """
        Function which fill in  KRBTGT keys in KRBTGT_keys_dict.
        We get the keys form the keytab file by using keytabParser module.
        :param keytab_path: The keytab file path.
        :return:
        """

        # Read the keytab file and init a KeyTab object.
        keytab = keytab_parser.KeyTab(keytab_path)
        # Get KRBTGT account keys.
        keys_list = keytab.get_keys_by_spn(KRBTGT_ACCOUNT_NAME)
        # If no keys were parsed we cannot start with the detection process.
        if not keys_list:
            raise FailedParsingKeysError(CANT_CHECK_ST_MSG)

        # Update keys in the keys dictionary.
        for key in keys_list:
            # Check whether the key algorithm is supported.
            if key.get_algo() in key_types_proxy:
                cls.KRBTGT_keys_dict[key_types_proxy[key.get_algo()]] = key.get_secret()

        # No KRBTGT keys were found, we can't proceed in the detection process.
        if not cls.KRBTGT_keys_dict:
            raise FailedParsingKeysError(CANT_CHECK_ST_MSG)

    @classmethod
    def __append_key_info(cls, keys_info_list, packet):
        """
        Add the information of a key (compromised or missing)to a list.
        If The key information is already in the list, we just adding the packet id.
        Each item in the list contain the following dictionary :
        {spn:
        key_algo:
        packet_numbers: []
        }

        :param list_to_append: List of dictionaries with keys information that are compromised or missing.
        :param packet: Packet that an attack execution was detected at or skipped.
        :return:
        """
        # The service name that it's key is compromised or missing.
        sname = get_dict_key_value(packet, SNAME_KEY_NAME)
        # The key algorithm type that is compromised or missing.
        key_algo = crypto._get_enctype_profile(int(get_dict_key_value(packet, ENC_TYPE_KEY_NAME)))
        key_algo_name = key_algo.__name__
        # The packet id which an attack were detected at or wasn't decrypted.
        packet_id = int(get_dict_key_value(packet, FRAME_NUM_KEY_NAME))
        # Checking if the SPN and the key algorithm already exists in the list.
        # If so just adding the packet id to the packets list.
        for key in keys_info_list:
            if key[SPN_ELEMENT] == sname:
                if key[KEY_ALGO_ELEMENT] == key_algo_name:
                    # Dictionary with our spn and algorithm type was found.
                    # Adding the packet id.
                    key[PACKETS_ELEMENTS].append(packet_id)
                    return

        # Dictionary with our spn and key algorithm was not found, creating one.
        keys_info_list.append({SPN_ELEMENT: sname,
                         KEY_ALGO_ELEMENT: key_algo_name,
                         PACKETS_ELEMENTS: [packet_id]})

