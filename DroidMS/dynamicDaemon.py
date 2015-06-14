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
import sys, time, os, shutil, urllib2, json, base64, requests, datetime
from daemon import Daemon
import settings, emulator_control
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def getNewJob():
    sampleId = ''
    queueId = ''
    sampleFile = ''
    privacy = ''
    apkName = ''
    pkgName = ''
    # get the sampleID with the highest priority from the queue and update submission and queue table
    try:
        content = urllib2.urlopen(settings.MSURL+"/api/bot/queue/idle_dynamic/?format="+
                                  settings.MSAPIFORMAT+"&username="+settings.MSAPIUSER+"&api_key="+settings.MSAPIKEY)
        result = json.load(content)
        sampleId = result['sample_id']
        queueId = result['id']
        privacy = result['public']
        apkName = result['name']
        pkgName = result['pname']
        sampleFile = base64.b64decode(result['sample'])
        return (sampleId,queueId,sampleFile,privacy,apkName,pkgName)
    except Exception as e:
        print e
        return (sampleId,queueId,sampleFile,privacy,apkName,pkgName)

class MyDaemon(Daemon):
    def run(self):
        # what the daemon does while it is running
        while True:
            workingDir = settings.TMPDIR
            if not os.path.exists(workingDir):
                os.mkdir(workingDir)
            (sampleId,queueId,sampleFile,privacy,apkName,pkgName) = getNewJob()
            if str(sampleId) != '':
                fileSystemPosition = workingDir+apkName
                sampleFile2 = open(fileSystemPosition, 'wb')
                sampleFile2.write(sampleFile)
                sampleFile2.close()
                print time.strftime("%d.%m.%Y - %H:%M:%S", time.localtime())
                print "running " + str(sampleId)
                # create a fresh installation of the emulator
                shutil.copyfile(settings.DROIDBOXINITIALDIR + "system.img", settings.DROIDBOXDIR + "system.img")
                shutil.copyfile(settings.DROIDBOXINITIALDIR + "ramdisk.img", settings.DROIDBOXDIR + "ramdisk.img")
                shutil.copyfile(settings.DROIDBOXINITIALDIR + "userdata.img", settings.DROIDBOXDIR + "userdata.img")
                # start the dynamic analysis
                stime = str(datetime.datetime.today())
                emulator_control.runDynamic(sampleId, fileSystemPosition, pkgName, workingDir, sampleFile)
                # HTTP_POST -- queueId & dynamic_log & dynamic_report & screenshot
                dynamicLogFile = open(workingDir + "dynamic.log", 'rb')
                if os.path.isfile(workingDir + "screenshot.png"):
                    screenshot = open(workingDir + "screenshot.png", 'rb')
                else:
                    screenshot = open(settings.BOTDIR + "dummy.png", 'rb')
                pcap = open(workingDir + "traffic.pcap", 'rb')
                ltrace = open(workingDir + "ltrace.log", 'rb')
                netstat_report = open(workingDir + "netstat_report.json", 'rb')
                sqlite_file_names = emulator_control.copyDatabase(pkgName, workingDir)
                sqlite_files = dict()
                for (filename, idx) in zip(sqlite_file_names, range(len(sqlite_file_names))):
                    sqlite_files['sqlite_' + str(idx)] = open(filename, 'rb')
                payload = {'format': settings.MSAPIFORMAT,
                           'username': settings.MSAPIUSER,
                           'api_key': settings.MSAPIKEY,
                           'queueId': queueId,
                           'stime': stime,
                           'sqlite_files_count': len(sqlite_files)}
                files = {'log': dynamicLogFile,
                         'screenshot': screenshot,
                         'pcap': pcap,
                         'ltrace': ltrace,
                         'netstat_report': netstat_report}
                files.update(sqlite_files)
                r = requests.post(settings.MSURL+"/api/bot/queue/done_dynamic/", params=payload, files=files)
                print r.text
                print r.status_code
                print "------------------------------------------------------------------"
                shutil.rmtree(workingDir)
            else:
                time.sleep(300)

#########################################################################################
#                                  MAIN PROGRAMM                                        #
#########################################################################################			
if __name__ == "__main__":
    daemon = MyDaemon('/tmp/dynamicDaemon.pid')
    if len(sys.argv) == 2:
        if 'start' == sys.argv[1]:
            daemon.start()
        elif 'stop' == sys.argv[1]:
            daemon.stop()
        elif 'restart' == sys.argv[1]:
            daemon.restart()
        else:
            print "Unknown command"
            sys.exit(2)
        sys.exit(0)
    else:
        print "usage: %s start|stop|restart" % sys.argv[0]
        sys.exit(2)