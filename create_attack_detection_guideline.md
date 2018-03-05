# Guideline on creating new attack detection module.
The Tool is modular and designed to be expanded.
\
In order to create a new attack detection, a class that inherits from AttackDetection need to be created.
There is a simple interface that each attack detection needs to be written according to:
```python
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
```

Each attack detection must have:
*   protocol_key_name: The key name that holds the protocol name (example frame.protocols)

*   protocol_value: On which protocol the attack occurs (example when we need packets that use Kerberos spnego-krb5)

*   identify_keyword: Element that identify that an attack can be executed at the packet (example when AP-REQ is relevant kerberos.ap_req_element)

*   detect function: Function that gets list of packets and argparse object.
The detect function need to check for each packet if executing the attack detection is relevant, if so execute the detection on the packet.

