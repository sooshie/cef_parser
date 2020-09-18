#!/usr/bin/python
# Based on https://github.com/sooshie/cef_parser (MIT License)
# Upgraded to flatten CEF custom number/string keyspace.

import re
import sys
import json
import argparse

# Example:
# bash-3.2$ echo "Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232 cs1Label=Policy cs1=DropAll" | ./cef_parser.py
#{"src": "10.0.0.1", "Name": "worm successfully stopped", "spt": "1232", "dst": "2.1.2.2", "DeviceVendor": "security", "CEFVersion": "0", "SignatureID": "100", "Severity": "10", "DeviceProduct": "threatmanager", "DeviceVersion": "1.0", "Policy": "DropAll"}#
#
# bash-3.2$ echo "Sep 19 08:26:10 host CEF:0|security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232" | ./cef_parser.py -p "Severity, DeviceProduct, dst, src"
#{"src": "10.0.0.1", "dst": "2.1.2.2", "Severity": "10", "DeviceProduct": "threatmanager"}

# CEF variables/parsing determined from:
# http://mita-tac.wikispaces.com/file/view/CEF+White+Paper+071709.pdf
cef_keys = set([
'act',
'app',
'cnt',
'dvc',
'dvchost',
'dst',
'dhost',
'dmac',
'dntdom',
'dpt',
'dproc',
'duid',
'dpriv',
'duser',
'end',
'fname',
'fsize',
'in',
'msg',
'out',
'proto',
'rt',
'request',
'src',
'shost',
'smac',
'sntdom',
'spt',
'spriv',
'suid',
'suser',
'start',
'cat',
'cs1Label',
'cs2Label',
'cs3Label',
'cs4Label',
'cs5Label',
'cs6Label',
'cn1Label',
'cn2Label',
'cn3Label',
'deviceCustomDate1Label',
'deviceCustomDate2Label',
'cs1',
'cs2',
'cs3',
'cs4',
'cs5',
'cs6',
'cn1',
'cn2',
'cn3',
'deviceNtDomain',
'deviceDnsDomain',
'deviceTranslatedAddress',
'deviceMacAddress',
'deviceCustomeDate1',
'deviceCustomDate2',
'destinationDnsDomain',
'destinationTranslatedAddress',
'destinationTranslatedPort',
'deviceDirection',
'deviceExternalId',
'deviceFacility',
'deviceInboundInterface',
'deviceOutboundInterface',
'deviceProcessName',
'externalId',
'fileCreateTime',
'fileHash',
'fileId',
'fileModificationTime',
'filePath',
'fileType',
'oldfileCreateTime',
'oldfileHash',
'oldfileId',
'oldfileModificationTime',
'oldFilename',
'oldFilePath',
'oldfilePermission',
'oldfsize',
'oldfileType',
'requestClientApplication',
'requestCookies',
'requestMethod',
'sourceDnsDomain',
'sourceServiceName',
'sourceTranslatedAddress',
'sourceTranslatedPort'
])

def main():
    print_keys = set()
    infile = None

    parser = argparse.ArgumentParser(description="Process Mach-O files, perform clustering on them, and spit out Yara signatures.")
    parser.add_argument('-a', '--add',
                        help='CSV list of fields to add to the default CEF ones')
    parser.add_argument('-p', '--print_keys',
                        help='CSV list of fields to print, defaults to all (JSON-like output)')
    parser.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin)
    args = parser.parse_args()

    if args.add:
        add = args.add.replace(' ', '').split(',')
        for a in add:
            cef_keys.add(a)

    if args.print_keys:
        pk = args.print_keys.replace(' ', '').split(',')
        for p in pk:
            print_keys.add(p)

    if not args.infile.isatty():
        # interactive device
        infile = args.infile
    else:
        #open the file here
        infile = open(args.infile, 'r')

    tokenlist = "|".join(cef_keys)
    regex = re.compile('('+tokenlist+')=(.*?)\s(?:'+tokenlist+'|$)')

    for line in infile:
        parsed = {}
        final_parsed = {}
        tokens = re.split(r'(?<!\\)\|', line)
        Extension = ''
        if len(tokens) == 8:
            Extension = tokens[7] 
        if len(tokens) > 8:
            sys.stderr.write("Parsing error\n")
            sys.exit(1)
        parsed['CEFVersion'] = tokens[0].split('CEF:')[1]
        parsed['DeviceVendor'] = tokens[1]
        parsed['DeviceProduct'] = tokens[2]
        parsed['DeviceVersion'] = tokens[3]
        parsed['SignatureID'] = tokens[4]
        parsed['Name'] = tokens[5]
        parsed['Severity'] = tokens[6]

        continue_parsing = False
        if len(Extension) > 0:
            continue_parsing = True
        while continue_parsing:
            m = re.search(regex, Extension)
            try:
                k,v = m.groups() 
                parsed[k] = v
                Extension = Extension.replace(k+'='+v, '').lstrip()
            except AttributeError:
                continue_parsing = False

        o = {}
        for k in parsed:
            if "Label" in k and len(k) == len("csXLabel"):
                value_key = k[:3]
                final_parsed[parsed[k]] = parsed[value_key]
            if "cs" not in k[:2] and "cn" not in k[:2]:
                final_parsed[k] = parsed[k]
        if len(print_keys) > 0:
            for p in print_keys:
               o[p] = final_parsed[p]
        else:
            o = final_parsed
        print json.dumps(o)

    #close input file if one was opened
    if args.infile.isatty():
        infile.close()

if __name__ == "__main__":
    main()
