# -*- coding: utf-8 -*-
"""
    NetRay Main module.
    This module is the manager module.
    It organizes everything that is needed in order to detect attacks in a given decrypted pcap parsed to a json file.
    Execution Flow:
        *Validate paths and user input.
        *Initialize a logger.
        *Deserialize json file.
        *Create a list with each packet as a dictionary.
        *Executes attack detection modules that in ATTACK_DETECTIONS_TO_EXECUTE.
        *Log attack detections to console.

    In order to expand the tool, all you need to do is:
        1.Write an attack detection module.
        2.Import the module here.
        3.Add the class name to ATTACK_DETECTIONS_TO_EXECUTE list.

    Attack detection modules can be found in externals files, example - silverticket.py.

    Author: Hoorvitch Ido (@hoorvitch)
    Copyright: © 2018 CyberArk Software Ltd. All rights reserved
    License: License - NetRay is licensed under the Internal Use License-(https://github.com/cyberark/NetRay/blob/master/LICENSE)
"""


### IMPORTS ###
import argparse
import json
import os

from constants import *
from utils import handle_dict_dup_keys, create_logger, write_log
# Attack detection classes
from silverticket import SilverTicketDetection

### Consts ###
# Attacks detections which will be executed.
ATTACK_DETECTIONS_TO_EXECUTE = [SilverTicketDetection, ]


# Messages Const's
BAD_PATH_MSG                           = 'Bad path:{} ,Quitting!'
# Logging messages Consts
LOG_DESERIALIZE_START_MSG              = "Started Json deserialization"
LOG_DESERIALIZE_END_MSG                = "Finished Json deserialization"
LOG_RESULT_SUMMERY_MSG                 = "Execution result summery:"
LOG_EXCEPTION_HEAD_MSG                 = "The program stop because the following exception were thrown"
FAILED_TO_LOAD_JSON_MSG                = "Failed deserialize the Json, quitting."
# The script help msg.
TOOL_DESCRIPTION                       = """Welcome to NetRay.
Please enter a keytab and a Json of a decrypted and parsed captured traffic that are from the same time.
The script will detect if and which attacks were executed."""





def deserialize_json(json_file):
    """
    Deserialize a decoded capture traffic file.
    The Json file needs to be a parsed pcap that Kerberos decryption was taken place on.
    In the json, each packet is a record in a dictionary format.
    We deserialize_json the json to a list of packets.
    We handle duplicates keys name at handle_dict_dup_keys function.
    :param json_file:   Decoded capture traffic file path.
    :return:            List of dictionaries, each dictionary represent a packet.
    """

    # Write to log that the deserialize started.
    write_log(LOG_DESERIALIZE_START_MSG, 0, write_to_screen = True)
    json_file = open(json_file, 'r')

    # Parsing json.
    # The handle_dict_dup_keys function handles the duplicate keys.
    # We get a list of packets, each packet is a dictionary with all of the packet fields.
    deserialize_output = json.load(json_file,
                                      object_pairs_hook=handle_dict_dup_keys)

    # Write to log that the deserialize ended.
    write_log(LOG_DESERIALIZE_END_MSG, 0, write_to_screen = True)

    json_file.close()

    # Return the output in json format.
    return deserialize_output


def get_args():
    """
    Handles command line arguments and gets things started.
    :return:  argparse object that contains the user input.
    """


    def _check_path(path):
        """
        Validate that a path exists and it's a file.
        :param path: The path that need to be validate
        :return: The path if valid , raise an exception otherwise
        """

        # Check if there is a file with the given path.
        if not os.path.isfile(path):
            # There is no file with the given path.
            raise argparse.ArgumentTypeError(BAD_PATH_MSG.format(path))

        # There is a file in the given path.
        return path

    # Create a parser
    parser = argparse.ArgumentParser(description=TOOL_DESCRIPTION,
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-j', '--JsonPath',
                        metavar='',
                        type=_check_path,
                        help="Specify the Json path",
                        )

    parser.add_argument('-k', '--KeyTabPath',
                        metavar='',
                        type=_check_path,
                        required=True,
                        help="Specify keytab path",
                        default=KEYTAB_PATH)

    parser.add_argument('-l', '--LogFilePath',
                        metavar='',
                        required=False,
                        help="Specify log path",
                        default=LOG_FILE_PATH)

    # Parse the user input
    args = parser.parse_args()
    return args


def main():
    """
    This is the main function that call functions that:
    Parse args.
    Create a logger.
    Deserialize a json output.
    Call attack detection functions.
    Log the run output to the console.
    :return:
    """

    # Parse the user input.
    args = get_args()
    # Create and configure a logger.
    create_logger(args.LogFilePath)

    try:
        # Deserialize a decoded capture traffic file.
        packets_list = deserialize_json(args.JsonPath)
    # Deserialization failed, quitting.
    except ValueError():
        write_log(FAILED_TO_LOAD_JSON_MSG, is_warning=True)
        return

    # List which will contain the attack detections result.
    execution_output = []
    trace = ''
    try:
        # Execute the detect function from each attack detection class.
        for attack in ATTACK_DETECTIONS_TO_EXECUTE:
            # Add the result of a detection to the final output.
            execution_output.append(attack.detect(packets_list, args))
    # If unhandled exception was thrown we want to save it to the log at the finally stage.
    except:
        import traceback
        # Get the traceback of the exception.
        trace = traceback.format_exc()

    # Write the output we have until now even if an exception was raised.
    finally:
        if execution_output:
            # Write summery title to log.
            write_log(LOG_RESULT_SUMMERY_MSG, write_to_screen=True)
            # Write the results of each attack detection process to log.
            for output in execution_output:
                write_log(output, 1, write_to_screen = True)
        # If unhandled exception was thrown, log it also.
        if trace:
            write_log(trace, is_warning=True)

if __name__ == "__main__":
    main()
