#!/usr/bin/env python
#
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, The-Honeynet-Project, Mobile-Sandbox
# Author: Patrik Lantz (patrik@pjlantz.com),
# Michael Spreitzenbarth (research@spreitzenbarth.de)
# Paul Hofmann
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
# python system imports
import hashlib, json, re, sys, datetime, os, random, string
from analyzer.models import *
from raven.contrib.django.raven_compat.models import client

# global variables
CC = ''.join(map(unichr, range(0,32) + range(127,160)))

REPORT_FILE_PREFIXES = {
                        'DroidBox' : "dynamic",
                        'SQLite' : "sqlite",
                        }

class LogcatParseError(Exception):
    pass
#########################################################################################
#                              Regular Expressions                                      #
#########################################################################################
LOGCAT_LINE_REGEX = re.compile(r"""
                                ^(?P<timestamp>[-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?)
                                :
                                (?P<priority_level>[A-Z])/
                                (?P<tag>\w*)
                                \([ \t]*
                                (?P<pid>\d*)\):[ \t]*
                                (?P<message>.*)$""", re.X)

SQLITE_REGEX = re.compile(r"""
                                ^(?P<operation_type>\w+)[ \t]* took [ \t]*
                                (?P<duration_ms>\d+)ms
                                [ \t]*-[ \t]*
                                (?P<state>\w+), [ \t]*
                                (?P<var_list>.*)$
                                """, re.X)

SQLITE_SINGLE_VAR_REGEX = re.compile(r"""
                                ^(
                                (?P<var_name>\w+)
                                = )?
                                (?P<var_value>
                                    (\"[^\"]*\")   |  # string A with ""
                                    ('[^\']*')     |  # string B with ''
                                    ([\+\-]?\d+)   |  # integer
                                    (\[.*\])       |  # list
                                    (null)            # null
                                )
                                [ \t]* ,?  [ \t]*
                                """, re.X)

SQLITE_WINDOW_REGEX = re.compile(r"""
                                ^(?P<file_name>.*)
                                [ \t]*
                                (\{ [0-9a-f]+ \})$
                                """, re.X)
#########################################################################################
#                            SQLiteConnection Parsing                                   #
#########################################################################################
def parse_comma_separated_key_value_pairs_for_sqlite(var_list, with_keys=True):
    res_vars = dict() if with_keys else []
    idx = 0
    var_list_len = len(var_list)
    while idx < var_list_len:
        m_curr_var = SQLITE_SINGLE_VAR_REGEX.match(var_list[idx:])
        if m_curr_var is None:
            raise LogcatParseError("Unparsable variable list")
        idx += len(m_curr_var.group())
        var_name = m_curr_var.groupdict()['var_name']
        var_value = m_curr_var.groupdict()['var_value']
        if (with_keys and var_name is None) or (not with_keys and var_name is not None):
            raise LogcatParseError("name of variable given or not given in contrast to declaration of with_keys")
        if with_keys:
            res_vars[var_name] = interpret_sqlite_data_literal(var_value)
        else:
            res_vars.append(interpret_sqlite_data_literal(var_value))
    return res_vars

def interpret_sqlite_data_literal(literal):
    literal = literal.strip()
    if literal == 'null':
        return None
    if (literal.startswith('"') and literal.endswith('"')) or (literal.startswith("'") and literal.endswith("'")):
        return literal[1:-1]
    if literal.isdigit() or literal[1:].isdigit():
        return int(literal)
    if literal.startswith('[') and literal.endswith(']'):
        return parse_comma_separated_key_value_pairs_for_sqlite(literal[1:-1], with_keys=False)
    raise LogcatParseError("Unknown datatype of literal: %s" % literal)

def get_sqlite_filename_from_window(window):
    match_window = SQLITE_WINDOW_REGEX.match(window)
    if match_window is None:
        return None
    return match_window.groupdict()['file_name'].strip()

def parse_sqlite_logcat_message(message):
    match_sqlite = SQLITE_REGEX.match(message)
    if match_sqlite is None:
        raise LogcatParseError("This is no valid SQLiteConnection logcat message: %s" % message)
    var_list = match_sqlite.groupdict()['var_list']
    var_dict =  parse_comma_separated_key_value_pairs_for_sqlite(var_list, with_keys=True)
    # Inject some generated infos:
    var_dict['file_name'] = get_sqlite_filename_from_window(var_dict['window']) if 'window' in var_dict else None
    return var_dict
#########################################################################################
#                                DroidBox Parsing                                       #
#########################################################################################
def fileHash(f, block_size=2**8):
    """
    Calculate MD5,SHA-1, SHA-256
    hashes of APK input file
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    f = open(f, 'rb')
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
        sha1.update(data)
        sha256.update(data)
    return [md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()]

def hexToStr(hexStr):
    """
    Convert a string hex byte values into a byte string
    """
    dataBytes = []
    hexStr = ''.join(hexStr.split(" "))
    for i in range(0, len(hexStr), 2):
        dataBytes.append(chr(int(hexStr[i:i+2], 16)))
    return ''.join( dataBytes )

def decode(s, encodings=('ascii', 'utf8', 'latin1')):
    for encoding in encodings:
        try:
            return s.decode(encoding)
        except UnicodeDecodeError:
            pass
    return s.decode('ascii', 'ignore')

def getTags(tagParam, tags):
    """
    Retrieve the tag names found within a tag
    """
    tagsFound = []
    try:
        for tag in tags.keys():
            if tagParam & tag != 0:
                tagsFound.append(tags[tag])
    except:
        print "ERROR! no tags found for " + str(tagParam)
    return tagsFound

def parse_droidbox_logcat_message(message):
    message = message.strip()
    boxlog = message.split('DroidBox:')
    # FIXME: unparsable DroidBox lines
    if len(boxlog) > 1:
        try:
            return json.loads(decode(boxlog[1]))
        except:
            print "Omitted Droidbox message:"
            print message
            raise LogcatParseError("Omitted Droidbox message: %s" % message)
    else:
        raise LogcatParseError("This is no valid DroidBox logcat message: %s" % message)
    #if len(boxlog) > 1:
    #    return json.loads(decode(boxlog[1]))
    #else:
    #    raise LogcatParseError("This is no valid DroidBox logcat message: %s" % message)
 
#########################################################################################
#                                   Subreports                                          #
#########################################################################################
def subreport_sqlite_connection(priority_level, tag, pid, message):
    if tag != 'SQLiteConnection':
        return None
    try:
        return parse_sqlite_logcat_message(message)
    except LogcatParseError:
        return None

def subreport_droidbox(priority_level, tag, pid, message):
    try:
        return parse_droidbox_logcat_message(message)
    except LogcatParseError:
        return None
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def save_log_info_to_db(sampleID, dynamicReport_jsonFileName, hashValue, stime):
    try:
        etime = str(datetime.datetime.today())
        pwd = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(5))
        sampleEntry = Sample.objects.get(id = sampleID)
        queueEntry = Queue.objects.get(sample_id=sampleEntry, analyzer_type='dynamic').bot
        analyzerEntry, created = Analyzer.objects.get_or_create(name='DroidBox 4.1.1',
                                                                type='dynamic',
                                                                os='android',
                                                                tools_integrated='DroidBox 4.1.1 and Evasion',
                                                                machine_id=queueEntry)
        isPublic = Queue.objects.get(sample_id = sampleEntry, analyzer_type = 'dynamic').public
        Reports.objects.create(sample_id = sampleEntry,
                               filesystem_position = dynamicReport_jsonFileName,
                               type_of_report = 'dynamic',
                               analyzer_id = analyzerEntry,
                               os = 'android',
                               password = pwd,
                               status = 'done',
                               start_of_analysis = stime,
                               end_of_analysis = etime,
                               public = isPublic)
    except Exception, ex:
        print "Error while writing DroidBox report data to database!"
        print ex
        client.captureMessage(message='Error while writing DroidBox report data to database!',
                              level='error',
                              extra={'sha256':str(hashValue[2])},
                              tags={'file':'parseDynamicLogFile.py'})
        
def save_log_data_to_json(log_data, workingDir):
    saved_files = {}
    for report_category in log_data:
        try:
            reportDir = workingDir
            if not os.path.exists(reportDir):
                os.mkdir(reportDir)
            prefix = REPORT_FILE_PREFIXES[report_category]
            jsonFileName = reportDir + prefix + "_" + str(datetime.datetime.today()).split(' ')[0] + "_" \
                           + str(datetime.datetime.today()).split(' ')[1].split('.')[0].replace(':', '-') + ".json"
            jsonFile = open(jsonFileName, "a+")
            jsonFile.write(json.dumps(log_data[report_category]))
            jsonFile.close()
            saved_files[report_category] = jsonFileName
        except Exception, ex:
            print ex
            print "Error while writing DroidBox output to JSON!"
            client.captureMessage(message='Error while writing DroidBox output to JSON!',
                                  level='error',
                                  extra={'sha256':str(hashValue[2])},
                                  tags={'file':'parseDynamicLogFile.py'})
    return saved_files

def parse_logcat_line(log_line, subreporters=dict(), dismiss_message=False):
    match_logcat = LOGCAT_LINE_REGEX.match(log_line)
    if match_logcat is None:
        raise LogcatParseError("This is no valid logcat line")
    match_logcat_dict = match_logcat.groupdict()
    message = match_logcat_dict['message']
    priority_level = match_logcat_dict['priority_level']
    tag = match_logcat_dict['tag']
    pid = match_logcat_dict['pid']
    timestamp = float(match_logcat_dict['timestamp'])
    res_log_entry = {
                     'timestamp' : timestamp,
                     'priority_level' : priority_level,
                     'tag' : tag,
                     'pid' : pid,
                     'subreports' : dict()
                     }
    if not dismiss_message:
        res_log_entry['message'] = message
    for subreporter_id in subreporters:
        res_log_entry['subreports'][subreporter_id] = subreporters[subreporter_id](priority_level, tag, pid, message)
    return res_log_entry

def parse_log_to_memory(sampleID, workingDir, logFile, apkName, pkgName, stime):
    res_droidbox = {}
    res_sqlconnections = []
    sendsms = {}
    phonecalls = {}
    cryptousage = {}
    netbuffer = {}
    dexclass = {}
    dataleaks = {}
    opennet = {}
    sendnet = {}
    recvnet = {}
    fdaccess = {}
    servicestart = {}
    udpConn = []
    permissions = []
    enfperm = []
    recvsaction = {}
    accessedfiles = {}
    tags = { 0x1 :   "TAINT_LOCATION",      0x2: "TAINT_CONTACTS",        0x4: "TAINT_MIC",            0x8: "TAINT_PHONE_NUMBER",
             0x10:   "TAINT_LOCATION_GPS",  0x20: "TAINT_LOCATION_NET",   0x40: "TAINT_LOCATION_LAST", 0x80: "TAINT_CAMERA",
             0x100:  "TAINT_ACCELEROMETER", 0x200: "TAINT_SMS",           0x400: "TAINT_IMEI",         0x800: "TAINT_IMSI",
             0x1000: "TAINT_ICCID",         0x2000: "TAINT_DEVICE_SN",    0x4000: "TAINT_ACCOUNT",     0x8000: "TAINT_BROWSER",
             0x10000: "TAINT_OTHERDB",      0x20000: "TAINT_FILECONTENT", 0x40000: "TAINT_PACKAGE",    0x80000: "TAINT_CALL_LOG",
             0x100000: "TAINT_EMAIL",       0x200000: "TAINT_CALENDAR",   0x400000: "TAINT_SETTINGS" }
    dynLog = open(logFile).readlines()
    boot = False
    for logLine in dynLog:
        logLine = logLine.rstrip()
        try:
            if pkgName in logLine:
                boot = True
        except:
            print logLine
            continue
        if boot:
            try:
                log_line_data = parse_logcat_line(logLine, { 'SQLite' : subreport_sqlite_connection, 'DroidBox' : subreport_droidbox }, dismiss_message=True)
                subreports = log_line_data['subreports']
                timestamp = log_line_data['timestamp']
                if subreports['SQLite'] is not None:
               
                ## BEGIN SUBREPORT: SQLite ##
                    res_sqlconnections.append(subreports['SQLite'])
                ## END SUBREPORT: SQLite ##
                    
                if subreports['DroidBox'] is not None:
                
                ## BEGIN SUBREPORT: DroidBox ##
                    load = subreports['DroidBox']
                    try:
                        # DexClassLoader
                        if load.has_key('DexClassLoader'):
                            load['DexClassLoader']['type'] = 'dexload'
                            dexclass[timestamp] = load['DexClassLoader']
                        # service started
                        if load.has_key('ServiceStart'):
                            load['ServiceStart']['type'] = 'service'
                            servicestart[timestamp] = load['ServiceStart']
                        # received data from net
                        if load.has_key('RecvNet'):
                            host = load['RecvNet']['srchost']
                            port = load['RecvNet']['srcport']
                            if load['RecvNet'].has_key('type') and load['RecvNet']['type'] == 'UDP':
                                recvdata = {'type': 'net read', 'host': host, 'port': port, 'data': load['RecvNet']['data']}
                                recvnet[timestamp] = recvdata
                            else:
                                fd = load['RecvNet']['fd']
                                hostport = host + ":" + port + ":" + fd
                                if netbuffer.has_key(hostport):
                                    if len(netbuffer[hostport]) == 0:
                                        netbuffer[hostport] = str(timestamp) + ":"
                                    netbuffer[hostport] =  netbuffer[hostport] + load['RecvNet']['data']
                        # fdaccess
                        if load.has_key('FdAccess'):
                            accessedfiles[load['FdAccess']['id']] = load['FdAccess']['path']
                        # file read or write
                        if load.has_key('FileRW'):
                            if accessedfiles.has_key(load['FileRW']['id']) and not "/dev/pts" in accessedfiles[load['FileRW']['id']]:
                                load['FileRW']['path'] = accessedfiles[load['FileRW']['id']]
                                if load['FileRW']['operation'] == 'write':
                                    load['FileRW']['type'] = 'file write'
                                else:
                                    load['FileRW']['type'] = 'file read'
                                fdaccess[timestamp] = load['FileRW']
                        # opened network connection log
                        if load.has_key('OpenNet'):
                            if load['OpenNet'].has_key('type') and load['OpenNet']['type'] == 'UDP':
                                opennet[timestamp] = load['OpenNet']
                                ref = load['OpenNet']['desthost'] + load['OpenNet']['destport']
                                if ref not in udpConn:
                                    udpConn.append(ref)
                            else:
                                load['OpenNet']['type'] = 'net open'
                                opennet[timestamp] = load['OpenNet']
                                host = load['OpenNet']['desthost']
                                port = load['OpenNet']['destport']
                                fd = load['OpenNet']['fd']
                                netbuffer[host + ":" + port + ":" + fd] = ""
                        # closed socket
                        if load.has_key('CloseNet'):
                            host = load['CloseNet']['desthost']
                            port = load['CloseNet']['destport']
                            ref = host + ":" + port
                            if ref not in udpConn:
                                fd = load['CloseNet']['fd']
                                try:
                                    data = netbuffer[host + ":" + port + ":" + fd]
                                except KeyError:
                                    continue
                                stamp = float(data.split(":")[0])
                                dataBuffer = data.split(":")[1]
                                recvdata =  { 'type': 'net read', 'host': host, 'port': port, 'data': dataBuffer}
                                recvnet[stamp] = recvdata
                                netbuffer[host + ":" + port + ":" + fd] = ""
                            else:
                                ref.remove(ref)
                        # outgoing network activity log
                        if load.has_key('SendNet'):
                            if load['SendNet'].has_key('type') and load['SendNet']['type'] == 'UDP':
                                ref = load['SendNet']['desthost'] + load['SendNet']['destport']
                                if ref not in udpConn:
                                    udpConn.append(ref)
                                    opennet[timestamp] = load['SendNet']
                            load['SendNet']['type'] = 'net write'
                            sendnet[timestamp] = load['SendNet']
                        # data leak log
                        if load.has_key('DataLeak'):
                            if load['DataLeak']['sink'] == 'File':
                                if accessedfiles.has_key(load['DataLeak']['id']):
                                    load['DataLeak']['path'] = accessedfiles[load['DataLeak']['id']]
                            load['DataLeak']['type'] = 'leak'
                            dataleaks[timestamp] = load['DataLeak']
                        # sent sms log
                        if load.has_key('SendSMS'):
                            load['SendSMS']['type'] = 'sms'
                            sendsms[timestamp] = load['SendSMS']
                        # phone call log
                        if load.has_key('PhoneCall'):
                            load['PhoneCall']['type'] = 'call'
                            phonecalls[timestamp] = load['PhoneCall']
                        # crypto api usage log
                        if load.has_key('CryptoUsage'):
                            load['CryptoUsage']['type'] = 'crypto'
                            cryptousage[timestamp] = load['CryptoUsage']
                    except ValueError:
                        pass
                ## END SUBREPORT: DroidBox ##
                
            except LogcatParseError:
                continue
        else:
            continue
    # DONE READING LOG FILE #
            
    # generate hashes
    hashValue = fileHash(workingDir + 'samples/' + apkName)
    # Print file activity
    keys = fdaccess.keys()
    keys.sort()
    # print read operation activity
    readOperation = []
    for key in keys:
        temp = fdaccess[key]
        try:
            if temp['operation'] == 'read' \
                and "pipe:" not in hexToStr(temp['path']) \
                and "cmdline" not in hexToStr(temp['path']) \
                and "scriptlog.txt" not in hexToStr(temp['path']):
                filePath = hexToStr(temp['path'])
                readOperation.append([filePath,str(temp['data'])])
            else:
                continue
        except ValueError:
            pass
        except KeyError:
            pass
    # print write operation activity
    writeOperation = []
    for key in keys:
        temp = fdaccess[key]
        try:
            if temp['operation'] == 'write' \
                and "pipe:" not in hexToStr(temp['path']) \
                and "cmdline" not in hexToStr(temp['path']) \
                and "scriptlog.txt" not in hexToStr(temp['path']):
                filePath = hexToStr(temp['path'])
                writeOperation.append([filePath,str(temp['data'])])
            else:
                continue
        except ValueError:
            pass
        except KeyError:
            pass
    # print network activity
    network = []
    keys = opennet.keys()
    keys.sort()
    for key in keys:
        temp = opennet[key]
        try:
            if "/" in str(temp['desthost']):
                if len(str(temp['desthost']).split("/")) < 2:
                    desthost = str(temp['desthost']).split("/")[1]
                else:
                    desthost = str(temp['desthost'])
            else:
                desthost = str(temp['desthost'])
            network.append(["outgoing", desthost, str(temp['destport']), "open connection"])
        except ValueError:
            pass
        except KeyError:
            pass
    keys = sendnet.keys()
    keys.sort()
    for key in keys:
        temp = sendnet[key]
        try:
            if "/" in str(temp['desthost']):
                if len(str(temp['desthost']).split("/")) <= 2:
                    desthost = str(temp['desthost']).split("/")[1]
                else:
                    desthost = str(temp['desthost'])
            else:
                desthost = str(temp['desthost'])
            network.append(["outgoing", desthost, str(temp['destport']), hexToStr(temp['data'])])
        except ValueError:
            pass
        except KeyError:
            pass
    keys = recvnet.keys()
    keys.sort()
    for key in keys:
        temp = recvnet[key]
        try:
            if "/" in str(temp['host']):
                if len(str(temp['host']).split("/")) <= 2:
                    desthost = str(temp['host']).split("/")[1]
                else:
                    desthost = str(temp['desthost'])
            else:
                desthost = str(temp['host'])
            network.append(["incomming", desthost, str(temp['port']), hexToStr(temp['data'])])
        except ValueError:
            pass
        except KeyError:
            pass
    # Print sent SMSs
    sms = []
    keys = sendsms.keys()
    keys.sort()
    for key in keys:
        temp = sendsms[key]
        try:
            sms.append([str(temp['number']), str(temp['message'])])
        except ValueError:
            pass
        except KeyError:
            pass
    # Print phone calls
    phonecall = []
    keys = phonecalls.keys()
    keys.sort()
    for key in keys:
        temp = phonecalls[key]
        try:
            phonecall.append(str(temp['number']))
        except ValueError:
            pass
        except KeyError:
            pass
    # Print crypto API usage
    crypto = []
    keys = cryptousage.keys()
    keys.sort()
    for key in keys:
        temp = cryptousage[key]
        try:
            if temp['operation'] == 'keyalgo':
                crypto.append(["key", str(temp['key']), str(temp['algorithm'])])
            else:
                crypto.append([str(temp['operation']), str(temp['algorithm']), temp['data']])
        except ValueError:
            pass
        except KeyError:
            pass
    # print DexClass initializations
    dexclass2 = []
    keys = dexclass.keys()
    keys.sort()
    for key in keys:
        temp = dexclass[key]
        try:
            dexclass2.append(str(temp['path']))
        except ValueError:
            pass
        except KeyError:
            pass
    # print registered broadcast receivers
    broadcastrcv = []
    for recv in recvsaction:
        broadcastrcv.append([str(recv), str(recvsaction[recv])])
    # list started services
    service = []
    keys = servicestart.keys()
    keys.sort()
    for key in keys:
        temp = servicestart[key]
        if str(temp['name']) not in service:
            service.append(str(temp['name']))
    # print enforced permissions
    enfpermission = []
    for perm in enfperm:
        enfpermission.append(str(perm))
    # print bypassed permissions
    bypermission = []
    if len(recvnet.keys()) > 0 or len(sendnet.keys()) > 0 or len(opennet.keys()) > 0:
        if 'android.permission.INTERNET' not in permissions:
            bypermission.append("android.permission.INTERNET")
    if len(sendsms.keys()) > 0 and 'android.permission.SEND_SMS' not in permissions:
        bypermission.append("android.permission.SEND_SMS")
    if len(phonecalls.keys()) > 0 and 'android.permission.CALL_PHONE' not in permissions:
        bypermission.append("android.permission.CALL_PHONE")
    if 'android.provider.Telephony.SMS_RECEIVED' in recvsaction and 'android.permission.RECEIVE_SMS' not in permissions:
        bypermission.append("android.permission.RECEIVE_SMS")
    contacts = False
    phonestate = False
    sms2 = False
    book = False
    for k in dataleaks.keys():
        tagsInLeak = getTags(int(dataleaks[k]['tag'], 16), tags)
        if 'TAINT_CONTACTS' in tagsInLeak or 'TAINT_CALL_LOG' in tagsInLeak:
            contacts = True
        if 'TAINT_IMEI' in tagsInLeak:
            phonestate = True
        if 'TAINT_IMSI' in tagsInLeak:
            phonestate = True
        if 'TAINT_PHONE_NUMBER' in tagsInLeak:
            phonestate = True
        if 'TAINT_SMS' in tagsInLeak:
            sms2 = True
        if 'TAINT_BROWSER' in tagsInLeak:
            book = True
    if contacts and 'android.permission.READ_CONTACTS' not in permissions:
        bypermission.append("android.permission.READ_CONTACTS")
    if phonestate and 'android.permission.READ_PHONE_STATE' not in permissions:
        bypermission.append("android.permission.READ_PHONE_STATE")
    if sms2 and 'android.permission.READ_SMS' not in permissions:
        bypermission.append("android.permission.READ_SMS")
    if book and 'com.android.browser.permission.READ_HISTORY_BOOKMARKS' not in permissions:
        bypermission.append("com.android.browser.permission.READ_HISTORY_BOOKMARKS")
    # Print data leaks
    leaks = []
    keys = dataleaks.keys()
    keys.sort()
    for key in keys:
        temp = dataleaks[key]
        try:
            if temp['sink'] == 'Network':
                leaks.append(["network", str(temp['desthost']), str(temp['destport']), hexToStr(temp['data'])])
            if temp['sink'] == 'File':
                leaks.append(["file", hexToStr(temp['path']), str(temp['operation']), hexToStr(temp['data'])])
            if temp['sink'] == 'SMS':
                leaks.append(["sms", str(temp['number']), "", hexToStr(temp['data'])])
        except ValueError:
            pass
        except KeyError:
            pass
    if "/" in apkName:
        apkName = apkName.split("/")[-1]
    #Sort the items by their key
    res_droidbox["dexclass"] = dexclass
    res_droidbox["servicestart"] = servicestart
    res_droidbox["recvnet"] = recvnet
    res_droidbox["opennet"] = opennet
    res_droidbox["sendnet"] = sendnet
    #res_droidbox["closenet"] = closenet
    res_droidbox["accessedfiles"] = accessedfiles
    res_droidbox["dataleaks"] = dataleaks
    res_droidbox["fdaccess"] = fdaccess
    res_droidbox["sendsms"] = sendsms
    res_droidbox["phonecalls"] = phonecalls
    res_droidbox["cryptousage"] = cryptousage
    res_droidbox["recvsaction"] = recvsaction
    res_droidbox["enfperm"] = enfperm
    res_droidbox["hashes"] = hashValue
    res_droidbox["apkName"] = apkName
    return {
            'DroidBox' : res_droidbox,
            'SQLite' : res_sqlconnections,
            }
#########################################################################################
#                                 Main Functions                                        #
#########################################################################################
def parseLog(sampleID, workingDir, logFile, apkName, pkgName, stime):
    all_log_data = parse_log_to_memory(sampleID, workingDir, logFile, apkName, pkgName, stime)
    dump_more_sql_info(all_log_data, workingDir)
    hashVals = all_log_data['DroidBox']['hashes']
    saved_files = save_log_data_to_json(all_log_data, workingDir)
    save_log_info_to_db(sampleID, saved_files['DroidBox'], hashVals, stime)

def main():
    # For manual execution
    sampleID = sys.argv[1]
    workingDir = sys.argv[2]
    logFile = sys.argv[3]
    apkName = sys.argv[4]
    pkgName = sys.argv[5]
    stime = datetime.datetime.now()
    parseLog(sampleID, workingDir, logFile, apkName, pkgName, stime)
    
### BEGIN STAGING ###
def dump_more_sql_info(log_data, workingDir):
    import sql_parser
    table_file_assoc = {}
    filename = workingDir + "__sqlmore.json"
    for entry in log_data['SQLite']:
        file_name = entry['file_name'] \
                    if ('file_name' in entry) and (entry['file_name'] is not None) else \
                    None
        if ('sql' in entry) and (entry['sql'] is not None):
            table_name = sql_parser.get_table_name_from_query(entry['sql'])
            if table_name is not None:
                if table_name in table_file_assoc:
                    if file_name is not None:
                        table_file_assoc[table_name].add(file_name)
                else:
                    table_file_assoc[table_name] = set() if file_name is None else set([ file_name ])
                    print table_file_assoc  
    # make serializable  
    for table_name in  table_file_assoc:
        table_file_assoc[table_name] = list(table_file_assoc[table_name])
    jsonFile = open(filename, "wb")
    json.dump(table_file_assoc, jsonFile)
    jsonFile.close()
### END STAGING ###