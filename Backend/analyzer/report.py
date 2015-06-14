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
from analyzer.models import *
import datetime, random, string, json
from xml.dom import minidom
import certinfo, os, shutil
import parseDynamicLogFile, pcap_parser
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def processStatic(staticLogFile, staticReportFile, icon, sampleSHA256, sampleId, privacy, certFile):
    # wirte static log file to disk
    location = "/mobilesandbox/" + str(sampleSHA256) + "/log/"
    if not os.path.exists(location):
        os.mkdir(location)
    staticLogFileName = location + "static_" + str(datetime.datetime.today()).split(' ')[0] + "_" + \
                        str(datetime.datetime.today()).split(' ')[1].split('.')[0] + ".log"
    shutil.move(staticLogFile, staticLogFileName)
    # wirte static report file to disk
    location2 = "/mobilesandbox/" + str(sampleSHA256) + "/report/"
    if not os.path.exists(location2):
        os.mkdir(location2)
    staticReportFileName = location2 + "static_" + str(datetime.datetime.today()).split(' ')[0] + "_" + \
                           str(datetime.datetime.today()).split(' ')[1].split('.')[0] + ".json"
    shutil.move(staticReportFile, staticReportFileName)
    # write icon to disk
    shutil.move(icon, "/home/webinterface/analyzer/static/icons/" + str(sampleSHA256) + ".png")
    # write static analysis results to database
    # update submission database
    submissionEntry = Submission.objects.get(sample_id=int(sampleId))
    submissionEntry.status = 'done'
    submissionEntry.save()
    # get values from JSON report
    jsonData = json.loads(open(staticReportFileName).read())
    packageName = jsonData['package_name']
    ssdeepHash = jsonData['ssdeep']
    # update sample database
    sampleEntry = Sample.objects.get(id=int(sampleId))
    sampleEntry.status = 'done'
    sampleEntry.package_name = packageName
    sampleEntry.ssdeep = ssdeepHash
    sampleEntry.save()
    # update report database
    pwd = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(5))
    queueEntry = Queue.objects.get(sample_id=sampleEntry, analyzer_type='static').bot
    analyzerEntry, created = Analyzer.objects.get_or_create(name='DroidLyzer',
                                                            type='static',
                                                            os='android',
                                                            tools_integrated='DroidLyzer',
                                                            machine_id=queueEntry)
    reportEntry = Reports(sample_id=sampleEntry,
                          filesystem_position=staticReportFileName,
                          type_of_report='static',
                          analyzer_id=analyzerEntry,
                          os='Android',
                          password=pwd,
                          status='done',
                          start_of_analysis=datetime.datetime.today(),
                          end_of_analysis=datetime.datetime.today(),
                          public=int(privacy))
    reportEntry.save()
    # check if a certificate was inside the app
    if open(certFile, 'rb').read() != "None":
        # wirte certificate to disk
        certFileName = "/mobilesandbox/" + str(sampleSHA256) + "/log/cert"
        shutil.move(certFile, certFileName)
        # parse the certificate of the app
        certinfo.getCertInfos(certFileName, reportEntry)
    # update report_data database
    # insert used permissions
    for element in jsonData['app_permissions']:
        (permissionsEntry, created) = Permissions.objects.get_or_create(permission=element)
        UsedPermissions.objects.get_or_create(report_id=reportEntry, used_permission=permissionsEntry)
    # insert permissions needed corresponding to api calls
    for element in jsonData['api_permissions']:
        (permissionsEntry, created) = Permissions.objects.get_or_create(permission=element)
        NeededPermissions.objects.get_or_create(report_id=reportEntry, needed_permission=permissionsEntry)
    # insert intents
    for element in jsonData['intents']:
        (intentsEntry, created) = Intents.objects.get_or_create(intent=element)
        UsedIntents.objects.get_or_create(report_id=reportEntry, used_intent=intentsEntry)
    # insert Services&Receiver
    for element in jsonData['s_and_r']:
        (servicesAndReceiverEntry, created) = ServicesAndReceivers.objects.get_or_create(service_and_receiver=element)
        UsedServicesAndReceivers.objects.get_or_create(report_id=reportEntry, used_service_and_receiver=servicesAndReceiverEntry)
    # insert Activities
    for element in jsonData['activities']:
        (usedActivitiesEntry, created) = Activities.objects.get_or_create(activity=element)
        UsedActivities.objects.get_or_create(report_id=reportEntry, used_activity=usedActivitiesEntry)
    # insert API calls
    for element in jsonData['api_calls']:
        (usedAPICallEntry, created) = ApiCalls.objects.get_or_create(call=element)
        UsedApiCalls.objects.get_or_create(report_id=reportEntry, used_call=usedAPICallEntry)
    # insert hard coded URLs
    for element in jsonData['urls']:
        print element
        (urlEntry, created) = Urls.objects.get_or_create(url=element)
        UsedUrls.objects.get_or_create(report_id=reportEntry, used_url=urlEntry)
    return staticReportFileName

def processDynamic(pcap, dynamicLogFile, stime, screenshot, sampleEntry, ltrace):
    # wirte dynamic log file to disk
    location = "/mobilesandbox/" + str(sampleEntry.sha256) + "/log/"
    if not os.path.exists(location):
        os.mkdir(location)
    dynamicLogFileName = location + "dynamic_" + str(datetime.datetime.today()).split(' ')[0] + "_" + \
                         str(datetime.datetime.today()).split(' ')[1].split('.')[0] + ".log"
    shutil.move(dynamicLogFile, dynamicLogFileName)
    # wirte pcap file to disk
    pcapFileName = location + "traffic.pcap"
    shutil.move(pcap, pcapFileName)
    # wirte ltrace file to disk
    ltraceFileName = location + "ltrace.log"
    shutil.move(ltrace, ltraceFileName)
    # write screenshot to disk
    screenShotFileName = "/home/webinterface/analyzer/static/screenshots/" + str(sampleEntry.package_name) + ".png"
    shutil.move(screenshot, screenShotFileName)
    sampleId = sampleEntry.id
    location2 = "/mobilesandbox/" + str(sampleEntry.sha256) + "/"
    # parse dynamic log file and create JSON report
    parseDynamicLogFile.parseLog(sampleId, location2, dynamicLogFileName, sampleEntry.apk_name, sampleEntry.package_name, stime)
    # parse pcap file with pcap_parser
    pcap_parser.parse_from_file_to_db(pcapFileName, sampleEntry)