# -*- coding: utf-8 -*-
'''
Module for reading and parsing Heimdal keytab files.
See the following link for documentation on the file format.
https://www.h5l.org/manual/HEAD/krb5/krb5_fileformats.html

    Author: Hoorvitch Ido (@hoorvitch)
    Copyright: © 2018 CyberArk Software Ltd. All rights reserved
'''

# Imports
import os
from struct import unpack , calcsize
import time
import binascii


# Consts
UNKNOWN_ALGORITHM = 'unknown'
ENTRY_PRINT_FORMAT = "{KEY_VER}\t\t\t{KEY_TYPE}\t\t\t{SPN}\t\t\t{KEY}"
KEYTAB_COLUMNS ="Vno\t\t\tType\t\t\tPrincipal\t\t\tKEY\n"
# Messages
BAD_PATH_MSG = '\nBad path:{} ,Quitting!'
NOT_KEYTAB_MSG = 'The input file is not a valid keytab.'

# Key types
ENCTYPES = {
    1: 'des-cbc-crc',
    2: 'des-cbc-md4',
    3: 'des-cbc-md5',
    17: 'aes128-cts-hmac-sha1-96',
    18: 'aes256-cts-hmac-sha1-96',
    23: 'arcfour-hmac-md5'
    }

# SPN Types
NAMETYPES = {
    1: 'KRB5_NT_PRINCIPAL',
    2: 'KRB5_NT_SRV_INST',
    3: 'KRB5_NT_SRV_HST'
}

def _easy_unpack(fmt, keytab_file):
    """
    The function gets a struct format, calculate the size needed to be read and unpacking the struct.
    :param fmt: The unpacking format.
    :param keytab_file: File object to read from.
    :return: The unpacked struct.
    """

    return unpack(fmt, keytab_file.read(calcsize(fmt)))  # returns a tuple

class NotKeytabError(Exception):
    """Raised when the input file is not a valid keytab"""
    pass

class KeyTab(object):
    """
    A class that represent a keytab file.
    """
    # The keytab format (x501\x502)
    file_format_version = None  # uint16_t  (H)
    # List which the entries will be stored in.
    entries = []                # keytab_entry
    # The size in bytes of the keytab file
    size = None
    # File object of the keytab file.
    keytab_file = None


    def __init__(self, keytab_path):
        """
        Initialize the object with the file path.
        the file is being parsed at __init_read_entries__.
        :param keytab_path: the path of the keytab file.
        """
        # Validate and read the keytab file.
        self.__init_handle_file__(keytab_path)
        # Set the version of the keytab file.
        self.file_format_version, = unpack('>H', self.keytab_file.read(2))
        if self.file_format_version not in (0x501,0x502):
            raise NotKeytabError(NOT_KEYTAB_MSG)
        # Read the entries of the keytab file.
        self.__init_read_entries__(0x501 == self.file_format_version)


    def __init_read_entries__(self, is_old_format):
        """
        Reading the keytab entries until EOF.
        Parsing each entry.
        :param is_old_format: Boolean if the version of the keytab is 0x501
        :return:
        """
        # Checking if we reached EOF.
        while(self.size > self.keytab_file.tell()):
            # Read and parse a single entry.
            self.entries.append(KeyTabEntry(self.keytab_file, is_old_format))
        # Closing the file handle.
        self.keytab_file.close()


    def __init_handle_file__(self, keytab_path):
        """
        Validating the keytab path and getting it size.
        :param keytab_path: the keytab path.
        :return:
        """
        # Check that the given path is valid.
        if not os.path.isfile(keytab_path):
            raise Exception(BAD_PATH_MSG.format(keytab_path))

        # Get handle for the file.
        self.keytab_file = open(keytab_path, 'rb')
        # Get the file size.
        self.size = os.path.getsize(keytab_path)


    def get_keys_by_spn(self, spn):
        """
        Get the keys of certain SPN after the keytab was parsed.
        It takes all the keys of the input account\service is part of (krb as input will return krb@...).
        :param spn: the spn to get the keys of.
        :return:
        """

        result_list = []
        for entry in self.entries:
            # Check whether spn is in the key parsed principal.
            if spn.upper() == entry.parsed_components.upper():
                # It does, add it to the list.
                result_list.append(entry.key)
        if result_list:
            return  result_list

    def print_keytab(self):
        """
        Print the keytab content.
        :return:
        """
        if self.entries:
            print KEYTAB_COLUMNS
            for entry in self.entries:
                print entry


class KeyTabEntry(object):
    """
    A class that represent a keytab entry.
    KeyTab is composed from KeyTabEntries
    """

    size = None                 # int32_t (i)
    num_components = None       # uint16_t (H)                  #/* sub 1 if version 0x501 */
    realm = None                # counted_octet_string
    components = []             # counted_octet_string
    name_type = None            # uint32_t (I)                    #/* not present if version 0x501 */
    timestamp = None            # uint32_t (I)
    vno8 = None                 # uint8_t (B)
    key = None                  # keyblock
    vno = None                  # uint32_t (I)                   #/* only present if >= 4 bytes left in entry */
    flags = None                # uint32_t (I)                   #/* only present if >= 4 bytes left in entry */

    # Not part of the RFC, just for internal use.
    parsed_realm = None
    parsed_components = None
    parsed_timestamp = None
    parsed_principal = None     # servic name@relam

    def __init__(self, keytab_file, is_old_format):
        """
        reading a keytab entry by the format, at the end parsing the data.
        :param keytab_file:   File object to read from.
        :param is_old_format: Bool if the keytab is in an old format
        """
        self.name_type, self.vno, self.flags = None , None, None
        self.components = []
        # Get the entry size.
        self.size, = _easy_unpack('>i',keytab_file)
        offset = keytab_file.tell()
        # Get the number of components that the account\service name has.
        self.num_components, = _easy_unpack('>H', keytab_file)
        # At the keytab x501 format the number need to be decreased by one.
        if is_old_format:
            self.num_components -= 1
        # Get the Domain name.
        self.realm = CountedOctetString(keytab_file)
        # Read each account\service name components.
        for i in range(self.num_components):
            self.components.append(CountedOctetString(keytab_file))
        # Only exsits in the x502 keytab format.
        if not is_old_format:
            self.name_type, = _easy_unpack('>I', keytab_file)
        # Get the entry timestamp.
        self.timestamp, = _easy_unpack('>I', keytab_file)
        # Get the key version, each time a key is changed the version increased.
        self.vno8, = _easy_unpack('>B', keytab_file)
        # Get the entry secret key.
        self.key = KeyBlock(keytab_file)

        # optional attributes, only if more than 4 bytes left at the entry.
        if (keytab_file.tell() - offset <= self.size -4):
            self.vno, = _easy_unpack('>I', keytab_file)
            # only if more than 4 bytes left at the entry.
            if (keytab_file.tell() - offset <= self.size - 4):
                self.flags, = _easy_unpack('>I', keytab_file)

        # Parse the data that it will be easier to work with.
        self.parse()


    def parse(self):
        """
        Parsing the attributes after the entry was read.
        create variables that it is easier to work with.
        :return:
        """
        # Decode the realm in ASCII.
        self.parsed_realm = self.realm.data.decode("ascii")
        # Join the components with '/' after decoding the spn ASCII  .
        self.parsed_components = '/'.join(component.data.decode("ascii") for component in self.components)
        # Create  the principal that composed from COMPONENTS@RELAM.
        self.parsed_principal = "{COMPONENTS}@{REALM}".format(COMPONENTS=self.parsed_components,
                                                              REALM=self.parsed_realm )
        # Convert the name type to the matching name type string.
        if self.name_type in NAMETYPES:
            self.parsed_name_type = NAMETYPES[self.name_type]
        # Parse the timestamp to a readable format.
        self.parsed_timestamp = time.strftime("%Y-%m-%d ", time.gmtime(self.timestamp))


    def __str__(self):
        return ENTRY_PRINT_FORMAT.format(KEY_VER = self.vno,
                                                           KEY_TYPE = self.key.get_algo(),
                                                           SPN = self.parsed_principal,
                                                           KEY = self.key.get_secret())

class KeyBlock(object):
    """
    A class that represent a key block.
    """
    algo_type = None            # uint16_t(H)
    key = None                  # counted_octet_string

    # Not part of the RFC, just for internal use.
    parsed_key = None
    parsed_algorithm = None

    def __init__(self , keytab_file):
        """
        Reading the keyblock struct and then parse it.
        :param keytab_file:
        """
        self.algorithm_type, = _easy_unpack('>H', keytab_file)
        self.key = CountedOctetString(keytab_file)
        self.parse()

    def parse(self):
        """
        Parsing the attributes after the key block was read.
        create variables that it is easier to work with.
        :return:
        """
        # Parsing the key to hex string
        self.parsed_key = binascii.hexlify(bytearray(self.key.data))
        # If the key algorithm is from the common algorithms, parsing the number to algorithm name.
        if self.algorithm_type in ENCTYPES:
            self.parsed_algorithm = ENCTYPES[self.algorithm_type]
        else:
            # parsed_algo is UNKNOWN If the algorithm is not from the common algorithms
            self.parsed_algorithm = UNKNOWN_ALGORITHM

    def get_secret(self):
        """
        return the parsed key.
        :return:
        """
        return  self.parsed_key

    def get_algo(self):
        """
        return the parsed key algorithm.
        :return:
        """
        return self.parsed_algorithm


class CountedOctetString (object):
    """
    Class the represent CountedOctetString.
    CountedOctetString is a string struct that has length and byte array with that length.
    """
    length = None               # uint16_t (H)
    data   = None               # uint8_t(B) []


    def __init__(self, keytab_file):
        """
        Read the CountedOctetString.
        :param keytab_file: the file to read from.
        """
        # The length of the array.
        self.length, = _easy_unpack('>H', keytab_file)
        # Reading self.length bytes.
        self.data = _easy_unpack('>%dB' % self.length, keytab_file)
        self.parse()

    def parse(self):
        # Convert the data to bytearry.
        self.data = bytearray(self.data)

