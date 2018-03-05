# -*- coding: utf-8 -*-
"""
    Module that contains the core constants and general constants.

    Author: Hoorvitch Ido (@hoorvitch)
    Copyright: © 2018 CyberArk Software Ltd. All rights reserved
    License: License - NetRay is licensed under the Internal Use License-(https://github.com/cyberark/NetRay/blob/master/LICENSE)
"""

### Const's ###
import time
# The dictionary key that contains the packet protocol.
PROTO_KEY_NAME = 'frame.protocols'
# The dictionary key that contains the packet number.
FRAME_NUM_KEY_NAME = 'frame.number'

# Used in order to get the process output.
STDERR = 1
STDOUT = 0

# Logger configuration.
LOG_FILE_PATH = "NetRay_log_%s.log" % time.strftime("%Y-%m-%d_%H-%M-%S")
LOG_FORMAT = '%(asctime)s\t %(levelname)s\t%(message)s'
LOG_NAME = "MYLOG"

# Default Path
KEYTAB_PATH = ""



