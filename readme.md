
# NetRay
`NetRay` is a modular, python tool that detects attacks against the Kerberos protocol.
\
It takes a Json file of a parsed captured traffic and a keytab file and executes the attack detection modules.

*NetRay* is provided with a Silver Ticket attack detection module and it can be easily expanded.
\
More information about the potential in Kerberos decryption can be found in this [white paper](https://www.cyberark.com/resources/).


## Overview
The Kerberos authentication protocol holds an important role in an organizations' networks and it is an integral part of Microsoft domain’s networks.
As long as Kerberos communication is not being decrypted, attackers get an opportunity to act freely using Kerberos without being detected,
all the while the encryption is being handed on a silver platter. 

Kerberos decryption allows a better view of what is happening in the network.
This tool provides the blue side a simple approach to detect attacks against the protocol.


## Requirements:
For *NetRay* to run, Impacket module is required. 
- [Impacket](https://github.com/CoreSecurity/impacket):
    - For installing Impacket, run the following command:
        - ```python -m pip install impacket```

## Usage:
*NetRay* needs a json file and a keytab.
```
python .\NetRay.py  -h
usage: NetRay.py [-h] [-j] -k  [-l]

Welcome to NetRay.
Please enter a keytab and a Json of a decrypted and parsed captured traffic.
The script will detect if and which attacks were executed.

optional arguments:
  -h, --help           show this help message and exit
  -j , --JsonPath      Specify the Json path
  -k , --KeyTabPath    Specify keytab path
  -l , --LogFilePath   Specify log path

```

-   Json file
        
        The network must to be captured at a central point between the servers and the endpoints.
        The pcap must to be parsed with a tool that can decrypt kerberos on to Json format.
        As an example, Tshark can parse and decrypt a pcap file.
        TSHARK_BIN_PATH -r PCAP_PATH -K KEYTAB_PATH -T json kerberos > OUTPUT_JSON_PATH
	
	There are other tools that can be used, for an example - microsoft network monitor.

-   Keytab file


    The keytab is used to detect Silver Ticket attack. 
    The keytab must to contain the keys of the monitores services at the time of capture.
    The keytab must contain the KRBTGT account key.
    
    In order to create a keytab, Linux with updated samba installed is required.
    
    To install samba run the following command:
        \
    ```apt-get install samba ```
    \
    \
    To replicate the domain settings and secrets run the following command:
    \
    ```samba-tool drs clone-dc-database --include-secrets --targetdir=<outDirPath> <dominName> -U <userName>@<domainName> -k [yes]```
    \
    The flag -k states whether to use Kerberos for the replication process or not.
    After the execution, the following directory tree will be created at the outDirPath:
    ``` ls
        ls -la /home/me/dc_cloned/
        total 28
        drwxr-xr-x  6 root root 4096 Jan  2 18:49 .
        drwxr-xr-x 22 root root 4096 Jan  2 19:31 ..
        drwxr-xr-x  2 root root 4096 Jan  2 18:49 etc
        drwxr-xr-x  2 root root 4096 Jan  2 18:49 msg.lock
        -rw-r-----  1 root root  696 Jan  2 18:49 names.tdb
        drwxr-xr-x  5 root root 4096 Jan  2 18:49 private
        drwxr-xr-x  3 root root 4096 Jan  2 18:49 state
        ls -la /home/me/dc_cloned/etc/
        total 12
        drwxr-xr-x 2 root root 4096 Jan  2 18:49 .
        drwxr-xr-x 6 root root 4096 Jan  2 18:49 ..
        -rw-r--r-- 1 root root 1254 Jan  2 18:49 smb.conf
         ls -la /home/me/dc_cloned/private/
        total 10464
        drwxr-xr-x 5 root root    4096 Jan  2 18:49 .
        drwxr-xr-x 6 root root    4096 Jan  2 18:49 ..
        -rw-r--r-- 1 root root    3663 Jan  2 18:49 dns_update_list
        -rw------- 1 root root 1286144 Jan  2 18:49 hklm.ldb
        -rw------- 1 root root 1286144 Jan  2 18:49 idmap.ldb
        -rw-r--r-- 1 root root      90 Jan  2 18:49 krb5.conf
        drwx------ 2 root root    4096 Jan  2 18:49 msg.sock
        -rw------- 1 root root 1286144 Jan  2 18:49 privilege.ldb
        -rw------- 1 root root 4247552 Jan  2 18:49 sam.ldb
        drwx------ 2 root root    4096 Jan  2 18:49 sam.ldb.d
        -rw------- 1 root root 1286144 Jan  2 18:49 secrets.ldb
        -rw------- 1 root root     696 Jan  2 18:49 secrets.tdb
        -rw------- 1 root root 1286144 Jan  2 18:49 share.ldb
        -rw-r--r-- 1 root root     955 Jan  2 18:49 spn_update_list
        drwx------ 2 root root    4096 Jan  2 18:49 tls
    ```
    To export the replicated secrets to a keytab file run the following command:
    ```
    samba-tool domain exportkeytab <outputKeytabPath> -s <outDirPath/etc/smb.conf>
    ```
    \
    Now you have a keytab that can be provided to the tool.
    \
    I would like to thank Alva Lease 'Skip' Duckwall IV and Christopher Campbel for a [great blog post](http://passing-the-hash.blogspot.co.il/2016/06/nix-kerberos-ms-active-directory-fun.html).

    

## Example usage:
Tested with Python 2 on Linux and Windows
```
python \NetRay.py  -j ./parsed_json  -k ./my_keytab -l ./lan_log

2018-01-02 06:51:42,034  INFO   Started Json deserialization.
2018-01-02 06:51:43,449  INFO   Finished Json deserialization.
2018-01-02 06:51:43,449  INFO   Started Silver Ticket detection.
2018-01-02 06:51:43,611  INFO   Finished Silver Ticket detection.
2018-01-02 06:51:43,611  INFO   Execution result summery:
2018-01-02 06:51:43,611  INFO       Silver Ticket attack detection execution finished with the following results:
						                Silver Ticket was detected by invalid checksum. The following accounts were compromised :
							                SPN: server2016	Key algorithm:_AES256CTS	Packet numbers:[108]

```
**j** - Json file path

**k**  - Keytab file path

**l**   - log file path

## Code flow  :
The tool input is a Json parsed pcap file and a keytab. It deserializes the file into a list of packets (each packet is a nested dictionary). Then, each attack detection module is called with the packets list and the parsed args. At last, the detection results are being printed to the user.

## Infrastructure content
- constants: Consts That are not specific for a certain module
- NetRay: The main brain , desiralizes parsed captured traffic and calls the attack detection modules.
- keytabParser: Proprietary modules used to parse a keytab file without an external binary.
- silverticket: Silver Ticket attack detection module.
- utils - General functions.


## Contributions

`NetRay` detects Silver Ticket at the moment, as a POC.
 We highly encourage you to contribute with new detection modules for more attacks.

 

Please read through our [contributing guidelines](https://github.com/cyberark/NetRay/blob/master/create_attack_detection_guideline.md). Included is a guideline on creating new attack detection module.

## Contact Us
Whether you want to report a bug or share some
suggestions, drop me a line at
ido.hoorvitch@cyberark.com


