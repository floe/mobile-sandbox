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
import sys, time, os, shutil, urllib2, json, base64, requests, glob
from daemon import Daemon
import staticAnalyzer, settings
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def getNewJob():
    sampleId = ''
    queueId = ''
    sampleFile = ''
    privacy = ''
    apkName = ''
    # get the sampleID with the highest priority from the queue and update submission and queue table
    try:
        content = urllib2.urlopen(settings.MSURL+"/api/bot/queue/idle_static/?format="+
                                  settings.MSAPIFORMAT+"&username="+settings.MSAPIUSER+"&api_key="+settings.MSAPIKEY)
        result = json.load(content)
        sampleId = result['sample_id']
        queueId = result['id']
        privacy = result['public']
        apkName = result['name']
        sampleFile = base64.b64decode(result['sample'])
        return (sampleId,queueId,sampleFile,privacy,apkName)
    except Exception as e:
        print e
        return (sampleId,queueId,sampleFile,privacy,apkName)

class MyDaemon(Daemon):
    def run(self):
        # what the daemon does while it is running
        while True:
            workingDir = settings.TMPDIR
            if not os.path.exists(workingDir):
                os.mkdir(workingDir)
            (sampleId,queueId,sampleFile,privacy,apkName) = getNewJob()
            if str(sampleId) != '':
                fileSystemPosition = workingDir+apkName
                sampleFile2 = open(fileSystemPosition, 'wb')
                sampleFile2.write(sampleFile)
                sampleFile2.close()
                print time.strftime("%d.%m.%Y - %H:%M:%S", time.localtime())
                print "running " + str(sampleId)
                # start the static analysis
                staticAnalyzer.run(fileSystemPosition, workingDir)
                # HTTP_POST -- queueId & static_log & static_report & icon
                staticLogFile = open(workingDir + "static.log", 'rb')
                staticReportFile = open(workingDir + "static.json", 'rb')
                if glob.glob(workingDir + "unpack/META-INF/*.RSA"):
                    certFile = open(glob.glob(workingDir + "unpack/META-INF/*.RSA")[0], 'rb')
                elif glob.glob(workingDir + "unpack/META-INF/*.DSA"):
                    certFile = open(glob.glob(workingDir + "unpack/META-INF/*.DSA")[0], 'rb')
                else:
                    certFile = "NONE"
                icon = open(workingDir + "icon.png", 'rb')
                payload = {'format': settings.MSAPIFORMAT,
                           'username': settings.MSAPIUSER,
                           'api_key': settings.MSAPIKEY,
                           'queueId': queueId}
                files = {'log': staticLogFile,
                         'report': staticReportFile,
                         'cert': certFile,
                         'icon': icon}
                r = requests.post(settings.MSURL+"/api/bot/queue/done_static/", params=payload, files=files)
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
    daemon = MyDaemon('/tmp/staticDaemon.pid')
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