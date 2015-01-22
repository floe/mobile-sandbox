#!/usr/bin/python
#
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
import settings
import os, hashlib, datetime, subprocess, shutil, re, json, ssdeep, csv
# global variables
CC = ''.join(map(unichr, range(0,32) + range(127,160)))
#########################################################################################
#                                    Functions                                          #
#########################################################################################
# create Log file
def createLogFile(logDir):
    if not os.path.exists(logDir):
        os.mkdir(logDir)
    logFile = open(logDir + "static.log", "a+")
    logFile.write("\n\n\n")
    logFile.write("              ___.   .__.__                                                .______.                                                  \n")
    logFile.write("  _____   ____\_ |__ |__|  |   ____               ___________    ____    __| _/\_ |__   _______  ___       ____  ____   _____        \n")
    logFile.write(" /     \ /  _ \| __ \|  |  | _/ __ \    ______   /  ___/\__  \  /    \  / __ |  | __ \ /  _ \  \/  /     _/ ___\/  _ \ /     \       \n")
    logFile.write("|  Y Y  (  <_> ) \_\ \  |  |_\  ___/   /_____/   \___ \  / __ \|   |  \/ /_/ |  | \_\ (  <_> >    <      \  \__(  <_> )  Y Y  \      \n")
    logFile.write("|__|_|  /\____/|___  /__|____/\___  >           /____  >(____  /___|  /\____ |  |___  /\____/__/\_ \  /\  \___  >____/|__|_|  /      \n")
    logFile.write("      \/           \/             \/                 \/      \/     \/      \/      \/            \/  \/      \/            \/       \n")
    logFile.write("\n")
    logFile.write("---------------------------------------------------------------------------------------------------------------------------------\n")
    logFile.write("\n\t" + "static analysis")
    logFile.write("\n\t" + str(datetime.datetime.today()).split(' ')[0] + "\t-\t" + str(datetime.datetime.today()).split(' ')[1].split('.')[0])
    logFile.write("\n\n")
    return logFile

# make local log entries
def log(logFile, file, message, type):
    if type == 0:
        logFile.write("\n")
        logFile.write("-----------------------------------------------------------------------\n")
        logFile.write("\t" + message + "\n")
        logFile.write("-----------------------------------------------------------------------\n")
    if type == 1:
        logFile.write("\t\t" + file + "\t" + message + "\n")

# log file footer
def closeLogFile(logFile):
    logFile.write("\n\n\n")
    logFile.write("---------------------------------------------------------------------------------------------------------------------------------\n")
    logFile.write("\t (c) by mspreitz 2015 \t\t www.mobile-sandbox.com")
    logFile.close()

# create ssdeep hashes
def hash(fileSystemPosition):
    try:
        ssdeepValue = ssdeep.hash_from_file(fileSystemPosition)
        return ssdeepValue
    except Exception as e:
        print str(e.message)
        ssdeepValue = "(None)"
        return ssdeepValue

# get permissions by used API
def checkAPIpermissions(smaliLocation):
    apiCallList = open(settings.APICALLS).readlines()
    apiPermissions = []
    apiCalls = []
    # create file-list of directory
    fileList = []
    for dirname, dirnames, filenames in os.walk(smaliLocation):
        for filename in filenames:
            fileList.append(os.path.join(dirname, filename))
    # parse every file in file-list and search for every API call in API-Call-List
    for file in fileList:
        try:
            file = re.compile('[%s]' % re.escape(CC)).sub('', file)
            smaliFile = open(file).read()
            for apiCall in apiCallList:
                apiCall = apiCall.split("|")
                if smaliFile.find(apiCall[0]) != -1:
                    try:
                        permission = apiCall[1].split("\n")[0]
                    except:
                        permission = ""
                    if (permission not in apiPermissions) and (permission != ""):
                        apiPermissions.append(permission)
                        apiCalls.append(apiCall)
                else:
                    continue
        except:
            print "File " + file + " has illegal characters in its name!"
            continue
    return (apiPermissions, apiCalls)

# copy the icon
def copyIcon(sampleFile, unpackLocation, workingDir):
    icon = "icon.png"
    manifest = subprocess.Popen([settings.AAPT, 'dump', 'badging', sampleFile],
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    manifest = manifest.communicate(0)[0].split("\n")
    for line in manifest:
        if "application:" in line:
            try:
                icon = line.split("icon='")[1].split("'")[0]
            except:
                continue
        else:
                continue
    try:
        inputFile1 = unpackLocation + "/" + icon
        outputFile = workingDir + "icon.png"
        shutil.copy(inputFile1, outputFile)
    except:
        inputFile1 = settings.EMPTYICON
        outputFile = workingDir + "icon.png"
        shutil.copy(inputFile1, outputFile)

# using baksmali
def dex2X(unpackLocation, tmpDir):
    # baksmali
    smaliLocation = tmpDir + "smali"
    os.mkdir(smaliLocation)
    baksmali = subprocess.Popen(['java', '-Xmx256M', '-jar', settings.BACKSMALI, '-o', smaliLocation, unpackLocation + "/classes.dex"])
    baksmali.wait()
    return smaliLocation

# get all used activities
# the first activity in the list is the MAIN activity
def getActivities(sampleFile):
    activities = []
    manifest = subprocess.Popen([settings.AAPT, 'dump', 'badging', sampleFile],
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    manifest = manifest.communicate(0)[0].split("\n")
    for line in manifest:
        if "activity" in line:
            try:
                activity = line.split("'")[1].split(".")[-1]
                activity = re.compile('[%s]' % re.escape(CC)).sub('', activity)
                activity = "." + activity
                activities.append(activity.encode('ascii','replace'))
            except:
                continue
        else:
            continue
    manifest = subprocess.Popen([settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    manifest = manifest.communicate(0)[0].split("\n")
    for i,line in enumerate(manifest):
        if "activity" in line:
            try:
                nextLine = manifest[i+2].split("=")[1].split('"')[1]
                nextLine = re.compile('[%s]' % re.escape(CC)).sub('', nextLine)
                if (nextLine not in activities) and (nextLine != ""):
                    activities.append(nextLine.encode('ascii','replace'))
                else:
                    continue
            except:
                continue
        else:
            continue
    return activities

# get the used features
def getFeatures(logFile, sampleFile):
    appFeatures = []
    sampleInfos = subprocess.Popen([settings.AAPT, 'd', 'badging', sampleFile],
                                   stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
    sampleInfos = sampleInfos.communicate(0)[0].split("\n")
    log(logFile, 0, "application features", 0)
    for sampleInfo in sampleInfos:
        if sampleInfo.startswith("uses-feature"):
            sampleFeature = sampleInfo.split("'")[1]
            sampleFeature = re.compile('[%s]' % re.escape(CC)).sub('', sampleFeature)
            log(logFile, "Feature:", sampleFeature, 1)
            if (sampleFeature not in appFeatures) and (sampleFeature != ""):
                appFeatures.append(sampleFeature.encode('ascii','replace'))
        else:
            continue
    return appFeatures

# get a list of files inside the apk
def getFilesInsideApk(sampleFile):
    appFiles = []
    xml= subprocess.Popen([settings.AAPT, 'list', sampleFile],
                          stdout=subprocess.PIPE,
                          stdin=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    xml = xml.communicate(0)[0].split("\n")
    for line in xml:
            try:
                files = line.split("\n")[0]
                files = re.compile('[%s]' % re.escape(CC)).sub('', files)
                if files != "":
                    appFiles.append(files.encode('ascii','replace'))
            except:
                continue
    return appFiles

# get intents
def getIntents(logFile, sampleFile):
    log(logFile, 0, "used intents", 0)
    appIntents = []
    xml= subprocess.Popen([settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
                          stdout=subprocess.PIPE,
                          stdin=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    xml = xml.communicate(0)[0].split("\n")
    i = 0
    for line in xml:
        if "intent" in line:
            try:
                intents = line.split("=")[1].split("\"")[1]
                intents = re.compile('[%s]' % re.escape(CC)).sub('', intents)
                log(logFile, "AndroidManifest", intents, 1)
                appIntents.append(intents.encode('ascii','replace'))
            except:
                continue
        else:
            continue
    return appIntents

# get network
def getNet(sampleFile):
    appNet = []
    xml= subprocess.Popen([settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
                          stdout=subprocess.PIPE,
                          stdin=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    xml = xml.communicate(0)[0].split("\n")
    i = 0
    for line in xml:
        if "android.net" in line:
            try:
                net = line.split("=")[1].split("\"")[1]
                net = re.compile('[%s]' % re.escape(CC)).sub('', net)
                if net != "":
                    appNet.append(net.encode('ascii','replace'))
            except:
                continue
        else:
            continue
    return appNet

# get the permissions from the manifest
# different from the permissions when using aapt d xmltree sampleFile AndroidManifest.xml ???
def getPermissions(logFile, sampleFile):
    appPermissions = []
    permissions = subprocess.Popen([settings.AAPT, 'd', 'permissions', sampleFile],
                                   stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
    permissions = permissions.communicate(0)[0].split("uses-permission: ")
    log(logFile, 0, "granted permissions", 0)
    i = 1
    while i < len(permissions):
        permission = permissions[i].split("\n")[0]
        permission = re.compile('[%s]' % re.escape(CC)).sub('', permission)
        log(logFile, "Permission:", permission, 1)
        i += 1
        if permission != "":
            appPermissions.append(permission)
    return appPermissions

# get providers
def getProviders(logFile, sampleFile):
    log(logFile, 0, "used providers", 0)
    appProviders = []
    xml= subprocess.Popen([settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
                          stdout=subprocess.PIPE,
                          stdin=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    xml = xml.communicate(0)[0].split("\n")
    for line in xml:
        if "provider" in line:
            try:
                provider = line.split("=")[1].split("\"")[1]
                provider = re.compile('[%s]' % re.escape(CC)).sub('', provider)
                log(logFile, "AndroidManifest", provider, 1)
                if appProviders != "":
                    appProviders.append(provider.encode('ascii','replace'))
            except:
                continue
        else:
            continue
    return appProviders

# get some basic information
def getSampleInfo(logFile, sampleFile):
    fp = open(sampleFile, 'rb')
    content = fp.read()
    md5OfNewJob = hashlib.md5(content).hexdigest()
    shaOfNewJob = hashlib.sha256(content).hexdigest()
    fp.close()
    appInfos = []
    log(logFile, 0, "application infos", 0)
    log(logFile, "sha256:", shaOfNewJob, 1)
    appInfos.append(shaOfNewJob)
    log(logFile, "md5:", md5OfNewJob, 1)
    appInfos.append(md5OfNewJob)
    sampleInfos = subprocess.Popen([settings.AAPT, 'd', 'badging', sampleFile],
                                   stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
    sampleInfos = sampleInfos.communicate(0)[0].split("\n")
    i = 0
    while i < len(sampleInfos):
        sampleInfo = sampleInfos[i]
        if sampleInfo.startswith("package: name="):
            sampleLable = sampleInfo.split("name=")[1].split("'")[1]
            appInfos.append(sampleLable.encode('ascii','replace'))
            log(logFile, "Label:", sampleLable, 1)
            break
        else:
            if i == (len(sampleInfos)-1):
                sampleLable = "NO_LABEL"
                log(logFile, "Label:", "no application label specified", 1)
                appInfos.append(sampleLable.encode('ascii','replace'))
                break
            else:
                i = i + 1
    i = 0
    while i < len(sampleInfos):
        sampleInfo = sampleInfos[i]
        if sampleInfo.startswith("sdkVersion"):
            sampleSdkVersion = sampleInfo.split("'")[1]
            log(logFile, "SDK version:", sampleSdkVersion, 1)
            appInfos.append(sampleSdkVersion)
            break
        else:
            if i == (len(sampleInfos)-1):
                sampleSdkVersion = "0"
                log(logFile, "SDK version:", "none specified", 1)
                appInfos.append(sampleSdkVersion)
                break
            else:
                i = i + 1
    apkName = str(sampleFile).split("/")[-1]
    appInfos.append(apkName.encode('ascii','replace'))
    return appInfos

# get services and receiver
def getServicesReceivers(logFile, sampleFile):
    log(logFile, 0, "used services and receivers", 0)
    servicesANDreceiver = []
    manifest = subprocess.Popen([settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    manifest = manifest.communicate(0)[0].split("\n")
    for i,line in enumerate(manifest):
        if "service" in line:
            try:
                nextLine = manifest[i+1].split("=")[1].split('"')[1]
                nextLine = re.compile('[%s]' % re.escape(CC)).sub('', nextLine)
                log(logFile, "AndroidManifest", nextLine, 1)
                if (nextLine not in servicesANDreceiver) and (nextLine != ""):
                    servicesANDreceiver.append(nextLine.encode('ascii','replace'))
            except:
                continue
        else:
            continue
    for i,line in enumerate(manifest):
        if "receiver" in line:
            try:
                nextLine = manifest[i+1].split("=")[1].split('"')[1]
                nextLine = re.compile('[%s]' % re.escape(CC)).sub('', nextLine)
                log(logFile, "AndroidManifest", nextLine, 1)
                if (nextLine not in servicesANDreceiver) and (nextLine != ""):
                    servicesANDreceiver.append(nextLine.encode('ascii','replace'))
            except:
                continue
        else:
            continue
    return servicesANDreceiver

# parsing smali-output for suspicious content
def parseSmaliCalls(logFile, smaliLocation):
    log(logFile, 0, "potentially suspicious api-calls", 0)
    dangerousCalls = []
    # create file-list of directory
    fileList = []
    for dirname, dirnames, filenames in os.walk(smaliLocation):
        for filename in filenames:
            fileList.append(os.path.join(dirname, filename))
    # parse every file in file-list
    for file in fileList:
        try:
            file = re.compile('[%s]' % re.escape(CC)).sub('', file)
            smaliFile = open(file).readlines()
            i = 0
            for line in smaliFile:
                i += 1
                if "Cipher" in line:
                    try:
                        prevLine = smaliFile[smaliFile.index(line) - 2].split("\n")[0].split('"')[1]
                        log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                        if "Cipher(" + prevLine + ")" in dangerousCalls:
                            continue
                        else:
                            dangerousCalls.append("Cipher(" + prevLine + ")")
                    except:
                        continue
                # only for logging !
                if "crypto" in line:
                    try:
                        line = line.split("\n")[0]
                        log(logFile, file + ":" + str(i), line, 1)
                    except:
                        continue
                if "Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;)" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "HTTP GET/POST (Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;))" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("HTTP GET/POST (Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;))")
                if "Ljava/net/HttpURLconnection" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "HttpURLconnection (Ljava/net/HttpURLconnection)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("HttpURLconnection (Ljava/net/HttpURLconnection)")
                if "getExternalStorageDirectory" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "Read/Write External Storage" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Read/Write External Storage")
                if "getSimCountryIso" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "getSimCountryIso" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("getSimCountryIso")
                if "execHttpRequest" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "execHttpRequest" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("execHttpRequest")
                if "Lorg/apache/http/client/methods/HttpPost" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "HttpPost (Lorg/apache/http/client/methods/HttpPost)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("HttpPost (Lorg/apache/http/client/methods/HttpPost)")
                if "Landroid/telephony/SmsMessage;->getMessageBody" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "readSMS (Landroid/telephony/SmsMessage;->getMessageBody)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("readSMS (Landroid/telephony/SmsMessage;->getMessageBody)")
                if "sendTextMessage" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "sendSMS" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("sendSMS")
                if "getSubscriberId" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "getSubscriberId" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("getSubscriberId")
                if "getDeviceId" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "getDeviceId" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("getDeviceId")
                if "getPackageInfo" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "getPackageInfo" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("getPackageInfo")
                if "getSystemService" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "getSystemService" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("getSystemService")
                if "getWifiState" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "getWifiState" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("getWifiState")
                if "system/bin/su" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "system/bin/su" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("system/bin/su")
                if "setWifiEnabled" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "setWifiEnabled" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("setWifiEnabled")
                if "setWifiDisabled" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "setWifiDisabled" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("setWifiDisabled")
                if "getCellLocation" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "getCellLocation" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("getCellLocation")
                if "getNetworkCountryIso" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "getNetworkCountryIso" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("getNetworkCountryIso")
                if "SystemClock.uptimeMillis" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "SystemClock.uptimeMillis" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("SystemClock.uptimeMillis")
                if "getCellSignalStrength" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "getCellSignalStrength" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("getCellSignalStrength")
                if "Landroid/os/Build;->BRAND:Ljava/lang/String" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "Access Device Info (Landroid/os/Build;->BRAND:Ljava/lang/String)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Access Device Info (Landroid/os/Build;->BRAND:Ljava/lang/String)")
                if "Landroid/os/Build;->DEVICE:Ljava/lang/String" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "Access Device Info (Landroid/os/Build;->DEVICE:Ljava/lang/String)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Access Device Info (Landroid/os/Build;->DEVICE:Ljava/lang/String)")
                if "Landroid/os/Build;->MODEL:Ljava/lang/String" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "Access Device Info (Landroid/os/Build;->MODEL:Ljava/lang/String)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Access Device Info (Landroid/os/Build;->MODEL:Ljava/lang/String)")
                if "Landroid/os/Build;->PRODUCT:Ljava/lang/String" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "Access Device Info (Landroid/os/Build;->PRODUCT:Ljava/lang/String)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Access Device Info (Landroid/os/Build;->PRODUCT:Ljava/lang/String)")
                if "Landroid/os/Build;->FINGERPRINT:Ljava/lang/String" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "Access Device Info (Landroid/os/Build;->FINGERPRINT:Ljava/lang/String)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Access Device Info (Landroid/os/Build;->FINGERPRINT:Ljava/lang/String)")
                if "adb_enabled" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "Check if adb is enabled" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Check if adb is enabled")
                # used by exploits and bad programers
                if "Ljava/io/IOException;->printStackTrace" in line:
                    log(logFile, file + ":" + str(i), line.split("\n")[0], 1)
                    if "printStackTrace" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("printStackTrace")
                if "Ljava/lang/Runtime;->exec" in line:
                    log(logFile, file + ":" + str(i), line, 1)
                    if "Execution of external commands (Ljava/lang/Runtime;->exec)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Execution of external commands (Ljava/lang/Runtime;->exec)")
                if "Ljava/lang/System;->loadLibrary" in line:
                    log(logFile, file + ":" + str(i), line, 1)
                    if "Loading of external Libraries (Ljava/lang/System;->loadLibrary)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Loading of external Libraries (Ljava/lang/System;->loadLibrary)")
                if "Ljava/lang/System;->load" in line:
                    log(logFile, file + ":" + str(i), line, 1)
                    if "Loading of external Libraries (Ljava/lang/System;->load)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Loading of external Libraries (Ljava/lang/System;->load)")
                if "Ldalvik/system/DexClassLoader;" in line:
                    log(logFile, file + ":" + str(i), line, 1)
                    if "Loading of external Libraries (Ldalvik/system/DexClassLoader;)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Loading of external Libraries (Ldalvik/system/DexClassLoader;)")
                if "Ldalvik/system/SecureClassLoader;" in line:
                    log(logFile, file + ":" + str(i), line, 1)
                    if "Loading of external Libraries (Ldalvik/system/SecureClassLoader;)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Loading of external Libraries (Ldalvik/system/SecureClassLoader;)")
                if "Ldalvik/system/PathClassLoader;" in line:
                    log(logFile, file + ":" + str(i), line, 1)
                    if "Loading of external Libraries (Ldalvik/system/PathClassLoader;)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Loading of external Libraries (Ldalvik/system/PathClassLoader;)")
                if "Ldalvik/system/BaseDexClassLoader;" in line:
                    log(logFile, file + ":" + str(i), line, 1)
                    if "Loading of external Libraries (Ldalvik/system/BaseDexClassLoader;)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Loading of external Libraries (Ldalvik/system/BaseDexClassLoader;)")
                if "Ldalvik/system/URLClassLoader;" in line:
                    log(logFile, file + ":" + str(i), line, 1)
                    if "Loading of external Libraries (Ldalvik/system/URLClassLoader;)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Loading of external Libraries (Ldalvik/system/URLClassLoader;)")
                if "android/os/Exec" in line:
                    log(logFile, file + ":" + str(i), line, 1)
                    if "Execution of native code (android/os/Exec)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Execution of native code (android/os/Exec)")
                if "Base64" in line:
                    log(logFile, file + ":" + str(i), line, 1)
                    if "Obfuscation(Base64)" in dangerousCalls:
                        continue
                    else:
                        dangerousCalls.append("Obfuscation(Base64)")
                else:
                    continue
        except:
            print "File " + file + " has illegal characters in its name!"
            continue
    return dangerousCalls

# parsing smali-output for URL's and IP's
def parseSmaliURL(logFile, smaliLocation):
    url = []
    # create file-list of directory
    fileList = []
    log(logFile, 0, "URL's and IP's inside the code", 0)
    for dirname, dirnames, filenames in os.walk(smaliLocation):
        for filename in filenames:
            fileList.append(os.path.join(dirname, filename))
    # parse every file in file-list
    for file in fileList:
        try:
            i = 0
            smaliFile = open(file).readlines()
            for line in smaliFile:
                try:
                    urlPattern = re.search('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line).group()
                    log(logFile, file + ":" + str(i), urlPattern, 1)
                    if (urlPattern not in url) and (urlPattern != ""):
                        url.append(urlPattern)
                    else:
                        continue
                except:
                    continue
                try:
                    ips = re.search('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', line).group()
                    log(logFile, file + ":" + str(i), ips, 1)
                    if (ips not in url) and (ips != ""):
                        url.append(ips)
                    else:
                        continue
                except:
                    continue
                i += 1
        except:
            print "File " + file + " has illegal characters in its name!"
            continue
    return url

# unpack the sample apk-file
def unpackSample(tmpDir, sampleFile):
    unpackLocation = tmpDir + "unpack"
    os.mkdir(unpackLocation)
    os.system("unzip " + "-q -d " + unpackLocation + " " + sampleFile)
    return unpackLocation

# check for Ad-Networks
def detect(smaliLocation):
    with open(settings.ADSLIBS, 'Ur') as f:
        smaliPath = list(tuple(rec) for rec in csv.reader(f, delimiter=';'))
    fileList = list()
    detectedAds = list()
    for dirname, dirnames, filenames in os.walk(smaliLocation):
        for filename in filenames:
            fileList.append(os.path.join(dirname, filename))
    for path in smaliPath:
        adPath = str(path[1])
        for file in fileList:
            if adPath in file:
                if (str(path[0]) not in detectedAds) and (str(path[0]) != ""):
                    detectedAds.append(str(path[0]))
                else:
                    continue
            else:
                continue
    return detectedAds

# create JSON file
def createOutput(workingDir, appNet, appProviders, appPermissions, appFeatures, appIntents, servicesANDreceiver, detectedAds,
                 dangerousCalls, appUrls, appInfos, apiPermissions, apiCalls, appFiles, appActivities, ssdeepValue):
    output = dict()
    output['md5'] = appInfos[1]
    output['sha256'] = appInfos[0]
    output['ssdeep'] = ssdeepValue
    output['package_name'] = appInfos[2]
    output['apk_name'] = appInfos[4]
    output['sdk_version'] = appInfos[3]
    output['app_permissions'] = appPermissions
    output['api_permissions'] = apiPermissions
    output['api_calls'] = apiCalls
    output['features'] = appFeatures
    output['intents'] = appIntents
    output['activities'] = appActivities
    output['s_and_r'] = servicesANDreceiver
    output['interesting_calls'] = dangerousCalls
    output['urls'] = appUrls
    output['networks'] = appNet
    output['providers'] = appProviders
    output['included_files'] = appFiles
    output['detected_ad_networks'] = detectedAds
    #save the JSON dict to a file for later use
    if not os.path.exists(workingDir):
        os.mkdir(workingDir)
    jsonFileName = workingDir + "static.json"
    jsonFile = open(jsonFileName, "a+")
    jsonFile.write(json.dumps(output))
    jsonFile.close()

#########################################################################################
#                                  MAIN PROGRAMM                                        #
#########################################################################################
def run(sampleFile, workingDir):
    # function calls
    logFile = createLogFile(workingDir)
    print "unpacking sample..."
    unpackLocation = unpackSample(workingDir, sampleFile)
    print "decompiling sample..."
    smaliLocation = dex2X(unpackLocation, workingDir)
    print "get Network data..."
    appNet = getNet(sampleFile)
    print "get sample info..."
    appInfos = getSampleInfo(logFile, sampleFile)
    print "get providers..."
    appProviders = getProviders(logFile, sampleFile)
    print "get permissions..."
    appPermissions = getPermissions(logFile, sampleFile)
    print "get activities..."
    appActivities = getActivities(sampleFile)
    print "get features..."
    appFeatures = getFeatures(logFile, sampleFile)
    print "get intents..."
    appIntents = getIntents(logFile, sampleFile)
    print "list files..."
    appFiles = getFilesInsideApk(sampleFile)
    print "get services and receivers..."
    servicesANDreceiver = getServicesReceivers(logFile, sampleFile)
    print "search for dangerous calls..."
    dangerousCalls = parseSmaliCalls(logFile, smaliLocation)
    print "get URLs and IPs..."
    appUrls = parseSmaliURL(logFile, smaliLocation)
    print "check API permissions..."
    apiPermissions = checkAPIpermissions(smaliLocation)
    print "crate ssdeep hash..."
    ssdeepValue = hash(sampleFile)
    print "check for ad networks..."
    detectedAds = detect(smaliLocation)
    print "create json report..."
    createOutput(workingDir,appNet,appProviders,appPermissions,appFeatures,appIntents,servicesANDreceiver,detectedAds,
                 dangerousCalls,appUrls,appInfos,apiPermissions[0],apiPermissions[1],appFiles,appActivities,ssdeepValue)
    print "copy icon file..."
    copyIcon(sampleFile, unpackLocation, workingDir)
    # programm and log footer
    print "close log-file..."
    closeLogFile(logFile)