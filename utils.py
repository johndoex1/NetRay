# -*- coding: utf-8 -*-
"""
    Module that contains handy functions that is used across modules.

    Author: Hoorvitch Ido (@hoorvitch)
    Copyright: © 2018 CyberArk Software Ltd. All rights reserved
    License: License - NetRay is licensed under the Internal Use License-(https://github.com/cyberark/NetRay/blob/master/LICENSE)
"""

### Imports ###
import logging
from constants import  *

### Consts ###
# Suffix that being added to duplicate keys name.
DUP_STR = "_dup_"

# Messages if a dictionary key was not found.
EMPTY_DICT_MSG = 'The var is not a dictionary'
KEY_NOT_FOUND_MSG = "Couldn't find key name {0} in: \n{1}"

# Logger formations
NEW_LINE_IN_BLOCK = '\n\t\t\t\t'

### Exceptions ###
class KeyNotFoundError(Exception):
    """Raised when the desired key was not found in the dictionary."""
    pass

#CR - check if what happen if not exists key and not strict?
def get_dict_key_value(dictionary, key_name, strict=True):
    """
    Recursive function which search for a dictionary key in a nested dictionary and return the first occurrence.
    If the key was not found None will be returned if strict flag is false, if the flag is on exception will be raised.
    :param dictionary: Dictionary to search in.
    :param key_name: The dictionary key to search for.
    :param strict: Whether or not to raise exception if the key was not found.
    :return: The key value if exists, None or exception otherwise.
    """
    # Stop if dictionary is not a dictionary type.
    if not isinstance(dictionary, dict):
        raise KeyNotFoundError(EMPTY_DICT_MSG)

    # Return our desired element in case it exists at the current level.
    if key_name in dictionary.keys():
        return dictionary[key_name]

    # Searching in sub dictionary's.
    for a_key in dictionary.keys():

        # Call ourselves with a "deeper" level of the dictionary.
        try:
            return get_dict_key_value(dictionary[a_key], key_name, strict)
        # The key wasn't found and strict is True
        except KeyNotFoundError:
            continue

    # The key was not found and not strict.
    if not strict:
        return

    # The key wasn't found and strict is True, so exception is being raised
    raise KeyNotFoundError(KEY_NOT_FOUND_MSG.format(key_name, str(dictionary)))

def handle_dict_dup_keys(ordered_pairs):
    """
    Dictionaries can't handle duplicates keys.
    In order to keep all the data from the json, we change key names at loading time.
    We take all key names in the same nesting level and
    add to the duplicates a unique suffix at the end.
    :param ordered_pairs: list of tuples from certain nesting level in a json record, each tuple is key name and value.
    :return: Dictionary without duplicate keys.
    """
    # Create an empty dictionary that will hold all the keys after the duplicated keys will be changed.
    dict_without_dup = {}
    for key_name, key_value in ordered_pairs:
        
        # Check if the key name is already exists.
        if key_name in dict_without_dup:
            counter = 0

            # In case that a key name exists more than two times.
            while (key_name + DUP_STR + str(counter) in dict_without_dup):
                counter += 1

            # Add the key to the dictionary after it was changed.
            dict_without_dup[key_name + DUP_STR + str(counter)] = key_value
        else:
            # First time that this key is found, add it to the dictionary.
            dict_without_dup[key_name] = key_value

    # Return a duplicate free dictionary.
    return dict_without_dup



def create_logger(log_file_path):
    """
    Function which initialize a logger
    The logger will log to screen and to a log file, and will be used across the different modules.
    :param log_file_path: the desired log file path.
    :return:
    """
    # Configure our specific logger
    logger = logging.getLogger(LOG_NAME)
    # Set the logger general level.
    logger.setLevel(logging.DEBUG)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create file handler
    file_handler = logging.FileHandler(log_file_path)
    file_handler.setLevel(logging.DEBUG)

    # Add formatter to both handlers.
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


def write_log(str_to_log,
              number_of_tabs = 0,
              write_to_file = True,
			  write_to_screen = False,
              is_warning = False):
    """
    Function which make the logging easier and the code more clear.
    We use it because there are times when we want to write only to screen or to file.
    When we log a big block of data (as a result of attack detection module) we want it to be look organized with tabs.
    :param str_to_log: The output that we want to log.
    :param number_of_tabs: The log indentation that the msg need to logged at.
    :param write_to_file: Bool : Is the msg should be logged to the file.
    :param write_to_screen: Bool: Is the msg should be logged to the screen.
    :param is_warning: Is the msg is a warning type msg.
    :return:
    """
    # Get our logger.
    logger = logging.getLogger(LOG_NAME)
    # Prepare the msg to be logged with the correct indentation.
    str_to_log = number_of_tabs * '\t' + str_to_log
    # If the msg is warning type write it as warning.
    if is_warning:
        logger.warning(str_to_log)
        return
    # In block of text that includes new line we add indentation because it don't have the logger info
    # Example to logger info (2017-09-26 01:40:03,808	 INFO	)
    str_to_log = str_to_log.replace('\n', NEW_LINE_IN_BLOCK)

    # If Logging to file.
    if write_to_file:
        # If Logging to screen.
        if write_to_screen:
            # Logging to screen and to file.
            logger.info(str_to_log)
            return
        else:
            # Logging only to file.
            logger.debug(str_to_log)
            return
    # Writing to screen not on logging way.
    print (str_to_log)


def hex_to_str(str):
    """
    Gets a string, remove byte separators and decode it as hex.
    :param str: string to be cleaned and decode.
    :return:decoded string
    """

    return str.replace(':','').decode('hex')










