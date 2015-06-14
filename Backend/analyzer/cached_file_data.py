#!/usr/bin/env python
#
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Author: Paul Hofmann
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#########################################################################################
#                          Imports  & Global Variables                                  #
#########################################################################################
import os
import json
from scapy.all import PcapReader

FILE_DATA_TYPES = {
                  'RAW' : { 'name' : 'RAW', 'needs_raw': True },
                  'JSON' : { 'name' : 'JSON', 'needs_raw': True },
                  'PCAP' : { 'name' : 'PCAP', 'needs_raw': False },
                  }

file_data = {}
#########################################################################################
#                                     Main Function                                     #
#########################################################################################

# This function should be introduced as an interface to load files since it keeps all loaded files in memory.
# So if you want to load the same file multiple times, it'll be loaded only once effectively.
# This could increase performance and decrease memory consumption significantly.
# Furthermore files can be loaded in different formats (parameter: data_type; also refer to the global variable FILE_DATA_TYPES):
#    RAW  : raw byte string
#    JSON : combination of lists and dictionaries as parsed from the given JSON-file
#    PCAP : list of Scapy packages as parsed from the given PCAP file

def get_file_data(filename, data_type='RAW', force_reload=False):
    if data_type not in FILE_DATA_TYPES:
        raise ValueError("Unknown data type %s" % data_type)
    data_type_info = FILE_DATA_TYPES[data_type]
    abs_file_path = os.path.abspath(filename)
    print abs_file_path
    if not os.path.isfile(abs_file_path):
        raise OSError("No such file: %s" % abs_file_path)
    data_id = (abs_file_path, data_type)
    data_id_as_raw = (abs_file_path, 'RAW')
    if (data_id not in file_data) or force_reload:
        # Drop reference in advance to avoid memory problems
        if data_id in file_data:
            file_data[data_id] = None
        print "Reading..."
        if data_type_info['needs_raw']:
            if (data_id_as_raw in file_data) and (file_data[data_id_as_raw] is not None):
                rawdata = file_data[data_id_as_raw]
            else:
                print "Reading RAW..."
                f = open(abs_file_path, "rb")
                rawdata = f.read()
                f.close() 
        else:
            rawdata = None
        if data_type == 'RAW':
            file_data[data_id] = rawdata
        elif data_type == 'JSON':
            file_data[data_id] = json.loads(rawdata)
        elif data_type == 'PCAP':
            pcapreader = PcapReader(abs_file_path)
            file_data[data_id] = [p for p in pcapreader]
    return  file_data[data_id] if data_id in file_data else None