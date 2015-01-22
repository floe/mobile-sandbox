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
import sys, time, os, urllib2, json, base64, requests
from daemon import Daemon
import avScan, settings
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def getNewJob():
    sampleId = ''
    queueId = ''
    sampleFile = ''
    privacy = ''
    # get the sampleID with the highest priority from the queue and update submission and queue table
    try:
        content = urllib2.urlopen(settings.MSURL+"/api/bot/queue/idle_av/?format="+settings.MSAPIFORMAT+
                                  "&username="+settings.MSAPIUSER+"&api_key="+settings.MSAPIKEY)
        result = json.load(content)
        sampleId = result['sample_id']
        queueId = result['id']
        privacy = result['public']
        sampleFile = base64.b64decode(result['sample'])
        return (sampleId,queueId,sampleFile,privacy)
    except:
        return (sampleId,queueId,sampleFile,privacy)

class MyDaemon(Daemon):
    def run(self):
        workingDir = "/tmp/"
        # what the daemon does while it is running
        while True:
            (sampleId,queueId,sampleFile,privacy) = getNewJob()
            if str(sampleId) != '':
                print time.strftime("%d.%m.%Y - %H:%M:%S", time.localtime())
                print "running " + str(sampleId)
                # start AV scan with the help of VirusTotal
                avScan.virustotal(sampleFile, workingDir, privacy)
                # HTTP_POST -- queueId & VirusTotal_Logfile
                vtLogFile = open(workingDir + "VirusTotal.log", 'rb')
                encodedLogFile = base64.b64encode(vtLogFile.read())
                vtLogFile.close()
                payload = {'format': settings.MSAPIFORMAT,
                           'username': settings.MSAPIUSER,
                           'api_key': settings.MSAPIKEY,
                           'queueId': queueId,
                           'log': encodedLogFile}
                r = requests.post(settings.MSURL+"/api/bot/queue/done_av/", params=payload)
                print r.text
                print r.status_code
                print "------------------------------------------------------------------"
                os.remove(workingDir + "VirusTotal.log")
            else:
                time.sleep(300)

#########################################################################################
#                                  MAIN PROGRAMM                                        #
#########################################################################################			
if __name__ == "__main__":
    daemon = MyDaemon('/tmp/avDaemon.pid')
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