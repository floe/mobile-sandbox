#!/usr/bin/env python
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Michael Spreitzenbarth (research@spreitzenbarth.de)
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
import os, subprocess, datetime, time, threading, re, random, json
import settings
# global variables
DATE = str(datetime.datetime.today()).split(' ')[0]
TIME = str(datetime.datetime.today()).split(' ')[1].split('.')[0]

logFile = None
start_timestamp = None

AWAITED_NETSTAT_HEADERS = { # The key tuples are assumed to be prefix-free (in the sense that each tuple entry is viewed as atomic)
                   ('Proto',) : 'Proto',
                   ('Recv-Q',) : 'Recv-Q',
                   ('Send-Q',) : 'Send-Q',
                   ('Local', 'Address',) : 'Local Address',
                   ('Foreign', 'Address',) : 'Foreign Address',
                   ('State',) : 'State',
                   ('User',) : 'User',
                   ('PID/Program', 'name',) : 'PID/Program name',
                   }
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def logcat_parser(pipe, workingDir, pkgName):
    global logFile, start_timestamp
    while True:
        if start_timestamp is None:
            start_timestamp = time.time()
        curr_ts = time.time() - start_timestamp
        line = pipe.readline()
        if line == "":
            closeLog()
            return
        logFile.write(str(curr_ts) + ":" +  line)
        if "DroidBox" in line:
            tmp = line.split(':')
            pid = re.search('\( *(\d*)\)',tmp[0]).group(1)
            msg = ":".join(tmp[2:])
            # TODO repair and test ltrace on Android 4.x
            '''
            if "ClassLoader" in msg and pkgName in msg and pkgName != "":
                print "----> app started with pid "+str(pid)+", launching ltrace ..."
                time.sleep(2)
                subprocess.Popen("adb shell 'chmod 777 /data/local/tmp/ltra*'", shell=True)
                subprocess.Popen("adb shell '/data/local/tmp/ltrace -F /data/local/tmp/ltrace.conf -p "+str(pid)+"' >> "+workingDir+"ltrace.log", shell=True)
                # FIXME: adding "-x open -x close -x read -x write -x socket" would also trace common libc calls, but seems to cause crashes
                print "----> ltrace running, writing to ltrace.log ..."
            '''

def header():
    print "----> starting dynamic analysis...."

def startEmulator(pcap, port, workingDir, pkgName):
    print "----> starting emulator\033[0;34m sandbox_4.1.1\033[m...."
    subprocess.Popen(['sh', settings.DROIDBOXDIR + 'test_emulator.sh', pcap, port])
    # test if emulator has started
    logcat = subprocess.Popen([settings.ADB, 'wait-for-device', 'logcat'],
                              bufsize=1,
                              stdout=subprocess.PIPE,
                              stdin=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    thread = threading.Thread(target=logcat_parser,
                              args=(logcat.stdout,workingDir,pkgName))
    thread.daemon = True
    thread.start()
    time.sleep(300)
    print "----> creating \033[0;34m" + pcap + "\033[m for network traffic recording...."

def useAppCustom(apk, pkgName, workingDir):
    use = subprocess.Popen(['monkeyrunner', settings.BOTDIR + 'monkey_control.py', apk, pkgName, workingDir])
    use.wait()
    rc = use.returncode
    return rc
    
def useAppMonkey(pkgName):
    print "----> using monkey within \033[0;34m" + pkgName + "\033[m"
    use = subprocess.Popen([settings.ADB, 'shell', 'monkey', '--throttle 100', '-p', pkgName, '-c android.intent.category.LAUNCHER', '100'])
    use.wait()
    time.sleep(20)

def simulateActionCall(port):
    print "----> simulate phone calls...."
    # receive a call and accept it
    for call in settings.CALLS:
        os.popen('echo gsm ' + call.split(":")[0] + ' ' + call.split(":")[1] + ' |nc localhost ' + port)
        time.sleep(random.randint(2,15))
    # change battery capacity
    os.popen('echo power capacity 73 |nc localhost ' + port)
    
def simulateActionSMS(port):
    print "----> simulate received sms...."
    # receive a sms
    for sms in settings.SMS:
        os.popen('echo sms ' + sms + ' |nc localhost ' + port)
        time.sleep(random.randint(1,8))

def simulateMovement(port):
    print "----> simulate movement with GPS...."
    # simulate movement
    for gps in settings.GPS:
        os.popen('echo geo fix ' + gps + ' |nc localhost ' + port)
        time.sleep(random.randint(2,15))
    # change battery capacity
    os.popen('echo power capacity 32 |nc localhost ' + port)

def initLog(logName):
    global logFile 
    logFile = open(logName, "a+")
    logFile.write("              ___.   .__.__                                                .______.                                                  \n")
    logFile.write("  _____   ____\_ |__ |__|  |   ____               ___________    ____    __| _/\_ |__   _______  ___       ____  ____   _____        \n")
    logFile.write(" /     \ /  _ \| __ \|  |  | _/ __ \    ______   /  ___/\__  \  /    \  / __ |  | __ \ /  _ \  \/  /     _/ ___\/  _ \ /     \       \n")
    logFile.write("|  Y Y  (  <_> ) \_\ \  |  |_\  ___/   /_____/   \___ \  / __ \|   |  \/ /_/ |  | \_\ (  <_> >    <      \  \__(  <_> )  Y Y  \      \n")
    logFile.write("|__|_|  /\____/|___  /__|____/\___  >           /____  >(____  /___|  /\____ |  |___  /\____/__/\_ \  /\  \___  >____/|__|_|  /      \n")
    logFile.write("      \/           \/             \/                 \/      \/     \/      \/      \/            \/  \/      \/            \/       \n")
    logFile.write("\n")
    logFile.write("----------------------------------------------------------------------------------------------------------------------------------------\n")
    logFile.write("\n\t" + "dynamic analyzer v2")
    logFile.write("\t\t" + DATE + "\t\t" + TIME + "\n")
    logFile.write("------------------------------------------------------------> "
                  "logcat start <------------------------------------------------------------\n")

def closeLog():
    logFile.write("-------------------------------------------------------------> "
                  "logcat end <-------------------------------------------------------------\n")
    logFile.write("(c) by mobilesandbox.org")
    logFile.close()
    
def stopEmulator():
    time.sleep(10)
    #killing processes that are used during the analysis and not always exited correctly
    subprocess.Popen([settings.ADB, 'emu', 'kill'],
                     stdout=subprocess.PIPE,
                     stdin=subprocess.PIPE,
                     stderr=subprocess.PIPE)
    subprocess.Popen(['killall', 'x11vnc'],
                     stdout=subprocess.PIPE,
                     stdin=subprocess.PIPE,
                     stderr=subprocess.PIPE)
    subprocess.Popen(['killall', 'Xvfb'],
                     stdout=subprocess.PIPE,
                     stdin=subprocess.PIPE,
                     stderr=subprocess.PIPE)

def footer():
    print "----> stopping dynamic analysis...."

def adb_list_directory(directory):
    process = subprocess.Popen([settings.ADB,  "shell", "ls '%s'; echo $?" % directory],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    split_stdout = stdout.split()
    dirs = split_stdout[:len(split_stdout)-2]
    returncode = split_stdout[len(split_stdout)-1]
    if returncode == '0':
        return dirs
    else:
        raise IOError("No such directory.") 
    
def adb_pull(remoteFile, localTargetFolder):
    process = subprocess.Popen([settings.ADB,  "pull", "%s" % remoteFile, "%s" % localTargetFolder])
    process.wait()
    if process.returncode != 0:
        raise IOError("Error during download.")

#TODO: NOT ALL DBs are found using this dirty approach
#TODO: untested - check if app is using a database. If it is using one, copy it to the backend and generate a view with the database design
def copyDatabase(pkgName, workingDir):
    DATA_ROOT_DIR = "/data/data"
    PACKAGE_DATA_DIR = os.path.join(DATA_ROOT_DIR, pkgName)
    PACKAGE_DATABASE_DIR = os.path.join(PACKAGE_DATA_DIR, "databases")
    LOCAL_DATABASE_DIR = os.path.join(workingDir, "databases")
    copied_files = []
    try:
        data_dirs = adb_list_directory(PACKAGE_DATA_DIR)
        if 'databases' in data_dirs:
            db_dir = adb_list_directory(PACKAGE_DATABASE_DIR)
            for fl in db_dir:
                if fl.lower().endswith('.db') or fl.lower().endswith('.sqlite') or fl.lower().endswith('.sqlite3'):
                    print "Found DB: %s" % fl
                    adb_pull(os.path.join(PACKAGE_DATABASE_DIR, fl), os.path.join(LOCAL_DATABASE_DIR, fl))
                    copied_files.append(os.path.join(LOCAL_DATABASE_DIR, fl))   
    except:
        print "Error during database search!"
    return copied_files

def getNetstatHeadersFromLine(header_line):
    splitted_headers = header_line.split()
    res_headers = []
    curr_fragment_buffer = []
    for header_fragment in splitted_headers:
        curr_fragment_buffer.append(header_fragment)
        curr_fragment_buffer_as_tuple = tuple(curr_fragment_buffer)
        if curr_fragment_buffer_as_tuple in AWAITED_NETSTAT_HEADERS:
            res_headers.append(AWAITED_NETSTAT_HEADERS[curr_fragment_buffer_as_tuple])
            curr_fragment_buffer = []
    if len(curr_fragment_buffer) > 0:
        raise ValueError("Unknown series of header fragments: %s" % str(curr_fragment_buffer))
    return res_headers
    
def getListeningPorts():
    res_natstat_entries = []
    process = subprocess.Popen(["adb", "shell",  "netstat –lntu; echo $?"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        raise OSError("Error during 'adb shell' execution")
    stdout_lines = stdout.splitlines()
    stdout_lines_length =  len(stdout_lines)
    if stdout_lines_length < 2:
        raise ValueError("netstat via ADB delivers insufficient input")
    header_line = stdout_lines[0]
    headers = getNetstatHeadersFromLine(header_line)
    inner_returncode = int(stdout_lines[-1])
    if inner_returncode != 0:
        raise OSError("Error during 'netstat' execution")
    content = stdout_lines[1:-1]
    for content_line in content:
        if content_line.isspace() or content_line == '':
            continue
        content_fragments = content_line.split()
        curr_netstat_entry = dict()
        if len(headers) != len(content_fragments):
            raise ValueError("Can't match headers to data in this entry. (unequal length)")
        for (header, content_fragment) in zip(headers, content_fragments):
            curr_netstat_entry[header] = content_fragment
        res_natstat_entries.append(curr_netstat_entry)
    return res_natstat_entries

def getNetstatDifference(before_data, after_data):
    diff_data = []
    for netstat_entry in after_data:
        if netstat_entry not in before_data:
            diff_data.append(netstat_entry)
    return diff_data

def copyNetstatReportToFile(workingDir, listening_ports):
    netstat_report_path = os.path.join(workingDir, 'netstat_report.json')
    report_file = open(netstat_report_path, 'wb')
    json.dump(listening_ports, report_file)
    report_file.close()

#########################################################################################
#                                  MAIN PROGRAMM                                        #
#########################################################################################
def runDynamic(sampleID, filesystemPosition, pkgName, workingDir, sampleFile):
    header()
    pcap = workingDir + "traffic.pcap"
    initLog( workingDir + "dynamic.log" )
    port = settings.EMULATORPORT
    apk = filesystemPosition
    startEmulator(pcap, port, workingDir, pkgName)
    netstat_data_before = getListeningPorts()
    rc = useAppCustom(apk, pkgName, workingDir)
    ltraceLog = open(workingDir + "ltrace.log", "a+")
    ltraceLog.close()
    if rc == 0:
        simulateActionCall(port)
        simulateActionSMS(port)
        useAppMonkey(pkgName)
        netstat_data_after = getListeningPorts()
        copyNetstatReportToFile(workingDir, getNetstatDifference(netstat_data_before, netstat_data_after))
        copyDatabase(pkgName, workingDir)
        stopEmulator()
    else:
        stopEmulator()
        time.sleep(15)
    footer()