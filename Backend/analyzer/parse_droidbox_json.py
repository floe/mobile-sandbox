#!/usr/bin/env python
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2013, Mobile-Sandbox
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
import binascii, pandas, datetime, json, string, itertools, sqlite_parser, os.path
#########################################################################################
#                               Helper Functions                                        #
#########################################################################################
def df_to_json(dataframe):
    d = dataframe.to_json(orient='records')
    json_data = json.dumps(json.loads(d), ensure_ascii=False).encode("utf-8")
    return  json_data

def get_working_directory(droidbox_json):
    sha256 = get_hashes(droidbox_json)[2]
    return "/mobilesandbox/%s" % sha256

def merge_dfs(dfs, merge_by, as_json=False):
    df_all = pandas.concat(dfs, ignore_index=True)
    if len(df_all) > 0:
        df_all.sort(merge_by, inplace=True)
    if as_json:
        df_all = df_to_json(df_all)
    return  df_all

def display_rawdata(rawdata):
    if not is_printable(rawdata):
        rawdata_bytes = ""
        for c in rawdata:
            rawdata_bytes += "%X " % ord(c)
        return rawdata_bytes
    else:
        return rawdata
    
def is_printable(thestr):
    for c in thestr:
        if c not in string.printable:
            return False
    return True

def get_human_readable_ts(fields):
    return [str(datetime.timedelta(seconds=(round(float(i.encode("utf-8")))))) for i in fields.keys()]

def unhex_data(fields):
    return [binascii.unhexlify(d) for d in fields]
#########################################################################################
#                              Generic Queries                                          #
#########################################################################################
def get_timestamped_data(droidbox_json, selector, columns, as_json=False, unhex_data_to_rawdata=False, transformer=None):
    timestamps = get_human_readable_ts(droidbox_json[selector])
    entries = [i[1] for i in droidbox_json[selector].items()]
    if len(entries) > 0:
        df_entries = pandas.DataFrame(entries, index=timestamps)
        df_entries.sort(inplace=True)
        df_entries.index.name='Timestamp'
        if transformer is not None:
            df_entries = transformer(df_entries)
        if unhex_data_to_rawdata:
            unhexed_data = unhex_data(df_entries['data'])
            df_entries['rawdata'] = unhexed_data
        df_entries = df_entries[columns].reset_index()
    else:
        df_entries = pandas.DataFrame()
    if as_json:
        df_entries = df_to_json(df_entries)
    return df_entries

def get_listed_data(droidbox_json, selector, as_json=False):
    result = [entry for entry in droidbox_json[selector]] 
    if as_json:
        result = json.dumps(result)
    return result

def get_dict_data(droidbox_json, selector, as_json=False):
    result = droidbox_json[selector]
    if as_json:
        result = json.dumps(result)
    return result
#########################################################################################
#                             Transform Functions                                       #
#########################################################################################
def dataleaks_transform(df):
    # Check all optional lists
    desthosts = df['desthost'] if 'desthost' in df.columns else []
    destports = df['destport'] if 'destport' in df.columns  else []
    paths = df['path'] if 'path'  in df.columns  else []
    operations = df['operation'] if 'operation' in df.columns  else []
    numbers =  df['number'] if 'number' in df.columns else []
    # Make readable tag list
    tag_list = []
    for tags in df['tag']:
        currStr = ""
        sep =""
        for tag in tags:
            currStr += sep + tag
            sep = ", "
        tag_list.append(currStr)
    df['tag_list'] = tag_list
    # Make context specific details
    details_list = []
    for (sink, desthost, destport, path, operation, number) in itertools.izip_longest(df['sink'], desthosts, destports, paths, operations, numbers):
        detail = sink
        if sink == 'Network':
            detail += " to %s:%s" % (desthost, destport)
        elif sink == 'File':
            detail += " %s to/from %s" % (operation, path)
        elif sink == 'SMS':
            detail += " to %s" % number
        details_list.append(detail)
    df['details'] = details_list
    return df

def crypto_transform(df):
    # Check all optional lists
    keys = df['key'] if 'key' in df.columns else []
    data_list = df['data'] if 'data' in df.columns else []
    # Merge keys and data
    key_or_data_list=[]
    for (op, key, data) in itertools.izip_longest(df['operation'], keys, data_list):
        if op=='keyalgo':
            key_or_data_list.append("KEY: %s" % key)
        else:
            key_or_data_list.append("DATA: %s" % data)
    df['key_or_data'] = key_or_data_list
    return df

def unhex_path_transform(df):
    df['path_unhexed'] = unhex_data(df['path'])
    return df
#########################################################################################
#                              Specific Queries                                         #
#########################################################################################
def get_apk_name(droidbox_json):
    return droidbox_json['apkName']

def get_permissions(droidbox_json, as_json=False):
    return get_listed_data(droidbox_json, 'enfperm', as_json)

def get_hashes(droidbox_json, as_json=False):
    return get_listed_data(droidbox_json, 'hashes', as_json)

def get_receivers(droidbox_json, as_json=False):
    return get_dict_data(droidbox_json, 'recvsaction', as_json)

def get_accessed_files(droidbox_json, as_json=False):
    return get_dict_data(droidbox_json, 'accessedfiles', as_json)

def get_unique_accessed_files(droidbox_json, as_json=False):
    files_dic = get_accessed_files(droidbox_json, as_json=False)
    files = set()
    for fid in files_dic:
        files.add(files_dic[fid])
    result = list(files)
    if as_json:
        result = json.dumps(result)
    return result

def get_dexclasses(droidbox_json, as_json=False):    
    return get_timestamped_data(droidbox_json, 'dexclass', ['path', 'type'], as_json)

def get_service_starts(droidbox_json, as_json=False):
    return get_timestamped_data(droidbox_json, "servicestart", ['type', 'name'], as_json)

def get_file_accesses(droidbox_json, as_json=False):
    return get_timestamped_data(droidbox_json, 'fdaccess', ['operation', 'path_unhexed', 'rawdata'], as_json, unhex_data_to_rawdata=True, transformer=unhex_path_transform)

def get_opened_network_connections(droidbox_json, as_json=False):
    return get_timestamped_data(droidbox_json, 'opennet', ['desthost', 'destport', 'fd'], as_json)

def get_sent_network_data(droidbox_json, as_json=False):
    return get_timestamped_data(droidbox_json, 'sendnet', ['desthost', 'destport', 'fd', 'operation', 'type', 'rawdata'], as_json, unhex_data_to_rawdata=True)
    
def get_received_network_data(droidbox_json, as_json=False):
    return get_timestamped_data(droidbox_json, 'recvnet', ['host', 'port', 'type', 'rawdata'], as_json, unhex_data_to_rawdata=True)

def get_crypto_usage(droidbox_json, as_json=False):
    return get_timestamped_data(droidbox_json, 'cryptousage', ['algorithm', 'key_or_data', 'operation', 'type'], as_json, transformer=crypto_transform)

def get_sent_sms(droidbox_json, as_json=False):
    return get_timestamped_data(droidbox_json, 'sendsms', ['message', 'type', 'number'], as_json)

def get_phonecalls(droidbox_json, as_json=False):
    return get_timestamped_data(droidbox_json, 'phonecalls', ['type', 'number'], as_json)

def get_dataleaks(droidbox_json, as_json=False):
    return get_timestamped_data(droidbox_json, 'dataleaks', ['sink', 'details', 'tag_list', 'rawdata'], as_json, unhex_data_to_rawdata=True, transformer=dataleaks_transform)

def get_sqlite_data(droidbox_json, as_json=False, withCols=True):
    wdir = get_working_directory(droidbox_json)
    db_wdir = os.path.join(wdir, 'databases')
    if os.path.exists(db_wdir):
        result = sqlite_parser.process_all_files(db_wdir, withCols)
    else:
        result = dict()
    if as_json:
        result = json.dumps(result)
    return result

#########################################################################################
#                               Activity Queries                                        #
#########################################################################################
def get_dataset_for_activity(df, columns, default_category=None, default_operation=None):
    if len(df) > 0:
        result = df.reset_index()[columns]
        if default_operation is not None:
            result['Operation'] = default_operation
        if default_category is not None:
            result['Category'] = default_category
        result.columns = ['Timestamp', 'Operation', 'Category']
    else:
        result = pandas.DataFrame()
    return result

def create_request_datset(df, is_send=False, is_receive=False):
    if is_send == is_receive:
        raise ValueError("Request can only be a sending or a receiving one. Not none and not both.")
    cols = [0,2,7] if is_send else [0,2,5]
    if len(df) > 0:
        req_ds = df.reset_index()[cols]
        req_ds['send_or_receive'] = "send" if is_send else "receive"
        req_ds.columns = ['Timestamp', 'endpoint', 'rawdata', 'send_or_receive']
    else:
        req_ds = pandas.DataFrame()
    return req_ds
    
def get_activity_data(droidbox_json, as_json=False):
    df_accessedfiles = get_file_accesses(droidbox_json)
    accessed_files = get_dataset_for_activity(df_accessedfiles, [1,2], default_category="file system")
    df_opennet = get_opened_network_connections(droidbox_json)
    network_open = get_dataset_for_activity(df_opennet, [1], default_category='network', default_operation='net open')
    df_sendnet = get_sent_network_data(droidbox_json)
    network_sent = get_dataset_for_activity(df_sendnet, [1,6], default_category='network')
    df_recvnet = get_received_network_data(droidbox_json)
    network_recv = get_dataset_for_activity(df_recvnet, [1,4], default_category='network')
    df_cryptousage = get_crypto_usage(droidbox_json)
    crypto_usage = get_dataset_for_activity(df_cryptousage, [1,2], default_category='crypto')
    df_dexclasses = get_dexclasses(droidbox_json)
    dexclasses = get_dataset_for_activity(df_dexclasses, [1,3], default_category='dexclasses')
    df_services = get_service_starts(droidbox_json)
    services = get_dataset_for_activity(df_services, [1], default_category='services', default_operation='started service')
    df_sms = get_sent_sms(droidbox_json)
    sms = get_dataset_for_activity(df_sms, [1,4], default_category='sms')
    df_phonecall = get_phonecalls(droidbox_json)
    calls = get_dataset_for_activity(df_phonecall, [1,2], default_category='phone')
    df_leaks = get_dataleaks(droidbox_json)
    leaks = get_dataset_for_activity(df_leaks, [1,2], default_category='dataleaks')
    return merge_dfs([accessed_files, network_open, network_sent, network_recv, crypto_usage, dexclasses, services, sms, calls, leaks], 'Timestamp', as_json)
    
def get_request_data(droidbox_json, as_json=False):
    df_sendnet = get_sent_network_data(droidbox_json)
    df_recvnet = get_received_network_data(droidbox_json)
    network_sent = create_request_datset(df_sendnet, is_send=True)
    network_recv = create_request_datset(df_recvnet, is_receive=True)
    return merge_dfs([network_sent, network_recv], 'Timestamp', as_json)
#########################################################################################
#                                Display Helper                                         #
#########################################################################################
def get_list_as_html(header_list=[], text_list=[], box_list=[]):
    if len(header_list) == 0 and len(text_list) == 0 and len(box_list) == 0:
        return "(None)"
    res = "<ul>"
    for (header, text, box) in itertools.izip_longest(header_list, text_list, box_list):
        res += "<li>"
        if header is not None:
            res += "<b>%s</b>" %header
        if text is not None:
            res += " " + text
        if box is not None:
            res += "<div style=\"border: 3px solid black; margin: 20px; padding: 5px\">%s</div>" % box
        res += "</li>"
    res += "</ul>"
    return res