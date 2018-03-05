# -*- coding: utf-8 -*-
"""
    Author: Hoorvitch Ido (@hoorvitch)
    Copyright: © 2018 CyberArk Software Ltd. All rights reserved
    License: License - NetRay is licensed under the Internal Use License-(https://github.com/cyberark/NetRay/blob/master/LICENSE)
"""

class AttackDetection(object):
    """
    This is the abstract class for attack detections. Every attack detection implementation should inherit from it.
    Each attack detection gets a list of packets and need to check whether an attack was executed.
    """
    # The name of the key at the json dictionary that contains the protocol name(where to look for).
    protocol_key_name = None
    # The current protocol name (what to look for)
    protocol_value = None
    # Keyword that identifies a packet as relevant for the current attack detection (filter style).
    identify_keyword = None

    def detect(cls, packet_list, parsed_argparse):
        """
        Function that detect whether an attack was executed.
        """
        raise NotImplementedError()

    def is_relevant(self):
        """
        Boolean function that checks if a packet or a stream is relevant for the current attack detection.
        True if a detection process is needed to be made.
        False otherwise
        """
        raise NotImplementedError()