#!/usr/bin/env python
#
#########################################################################################
#                                      Imports                                          #
#########################################################################################
import time, hashlib, os, shutil
import string, zipfile, datetime, subprocess
from analyzer.models import *
#########################################################################################
#                                 Global Variables                                      #
#########################################################################################
API_VERSION_HISTORY = {"0": "Android 1.0",
                       "1": "Android 1.0",
                       "2": "Android 1.1",
                       "3": "Android 1.5",
                       "4": "Android 1.6",
                       "5": "Android 2.0",
                       "6": "Android 2.0.1",
                       "7": "Android 2.1",
                       "8": "Android 2.2",
                       "9": "Android 2.3.0",
                       "10": "Android 2.3.4",
                       "11": "Android 3.0",
                       "12": "Android 3.1",
                       "13": "Android 3.2",
                       "14": "Android 4.0",
                       "15": "Android 4.0.4",
                       "16": "Android 4.1",
                       "17": "Android 4.2",
                       "18": "Android 4.3",
                       "19": "Android 4.4",
                       "20": "Android 4.4 Wear",
                       "xx": "Unknown"}
# live system
AAPT = '/usr/share/android-sdk/platform-tools/aapt'
#########################################################################################
#                               Helper Functions                                        #
#########################################################################################
def getAndroidVersion(basicsDict):
    apkFileInfos = subprocess.Popen([AAPT, 'd', 'badging', basicsDict['newFilename']],
                                    stdout=subprocess.PIPE,
                                    stdin=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
    apkFileInfos = apkFileInfos.communicate(0)[0].split("\n")
    sampleSdkVersion = 0
    androidVersion = "Android 1.0"
    for apkFileInfo in apkFileInfos:
        if apkFileInfo.startswith("sdkVersion"):
            sampleSdkVersion = apkFileInfo.split("'")[1]
            androidVersion = API_VERSION_HISTORY[sampleSdkVersion]
            break
    return sampleSdkVersion, androidVersion

def handleUploadedFile(fileName,tmpFile,isPublic,email,origin):
    basicsDict = {}
    basicsDict['error_message'] = 'OK'
    basicsDict['origin'] = origin
    fp = open(tmpFile, 'rb')
    content = fp.read()
    # check for valid apk file!
    try:
        a = zipfile.ZipFile(fp)
        for i in a.namelist():
            if i == "classes.dex":
                basicsDict['error_message'] = 'OK'
                break
            else:
                basicsDict['error_message'] = 'No valid Android apk file!'
    except:
        basicsDict['error_message'] = 'No valid apk file!'
    fp.close()
    # create a dictionary with important data from the submitted file
    newFilename = fileName
    newFilename = newFilename.replace(" ", "")
    newFilename = newFilename.replace("(", "")
    newFilename = newFilename.replace(")", "")
    newFilename = newFilename.replace("/", "")
    basicsDict['origfile'] = newFilename
    basicsDict['filesize'] = len(content)
    basicsDict['inserttime'] = int(time.time())
    basicsDict['md5'] = hashlib.md5(content).hexdigest()
    basicsDict['sha256'] = hashlib.sha256(content).hexdigest()
    # value of checkboxes
    basicsDict['isPublic'] = isPublic
    basicsDict['email'] = email
    # create folder structure and move TMP-file or display error message
    newFolderName = '/mobilesandbox/' + hashlib.sha256(content).hexdigest()
    newSampleFolder = newFolderName + '/samples'
    newFilename = filter(lambda x: x in string.printable, newFilename)
    newFilename = newSampleFolder + '/' + newFilename.replace(" ", "")
    basicsDict['newFilename'] = newFilename
    try:
        os.mkdir(newFolderName)
        os.mkdir(newSampleFolder)
        shutil.move(tmpFile, newFilename)
    except:
        if basicsDict['error_message'] == 'OK':
            try:
                sampleId = Sample.objects.get(sha256=basicsDict['sha256']).id
                basicsDict['error_message'] = 'This sample has already been uploaded with ID ' + str(sampleId) + '!'
            except:
                basicsDict['error_message'] = 'OK'
        else:
            print 'new sample submitted'
    # return the dictionary
    return basicsDict

def submissionSQL(basicsDict):
    if basicsDict['error_message'] == "OK":
        # check if user exists in DB already
        userEntry = User.objects.all().filter(email=basicsDict['email'])
        if not userEntry:
            userEntry = User.objects.create(email=basicsDict['email'],
                                            priority=0,
                                            name='anonymous',
                                            role='user')
            userEntry.save()
            priority = 0
        else:
            priority = userEntry[0].priority
            userEntry = userEntry[0]
        # get the minimum sdk version of the app
        sampleSdkVersion, androidVersion = getAndroidVersion(basicsDict)
        # check if sample exists in DB already
        sampleEntry = Sample.objects.all().filter(sha256=basicsDict['sha256'])
        if not sampleEntry:
            malwareFamilyEntry, created = MalwareFamily.objects.get_or_create(family_name='untested')
            sampleEntry = Sample.objects.create(apk_name=basicsDict['origfile'],
                                                md5=basicsDict['md5'],
                                                sha256=basicsDict['sha256'],
                                                filesystem_position=basicsDict['newFilename'],
                                                malware_family_id=malwareFamilyEntry,
                                                os='android',
                                                android_version=androidVersion,
                                                min_sdk_version = int(sampleSdkVersion),
                                                status='idle')
        else:
            sampleEntry = sampleEntry[0]
        # insert submission into the DB
        date_of_submission = datetime.datetime.fromtimestamp(basicsDict['inserttime']).strftime('%Y-%m-%d %H:%M:%S')
        Submission.objects.create(uploader_id=userEntry,
                                  sample_id=sampleEntry,
                                  os='android',
                                  status='idle',
                                  date_of_submission=date_of_submission,
                                  run_name=basicsDict['origfile'],
                                  public=basicsDict['isPublic'])
        # insert the sample into the queue
        Queue.objects.create(priority=priority,
                             analyzer_type='static',
                             sample_id=sampleEntry,
                             status='idle', bot='',
                             android_version=sampleEntry.android_version,
                             min_sdk_version = sampleEntry.min_sdk_version,
                             public=basicsDict['isPublic'])
        Queue.objects.create(priority=priority,
                             analyzer_type='dynamic',
                             sample_id=sampleEntry,
                             status='idle',
                             bot='',
                             android_version=sampleEntry.android_version,
                             min_sdk_version = sampleEntry.min_sdk_version,
                             public=basicsDict['isPublic'])
        Queue.objects.create(priority=priority,
                             analyzer_type='AV',
                             sample_id=sampleEntry,
                             status='idle',
                             bot='',
                             android_version=sampleEntry.android_version,
                             min_sdk_version = sampleEntry.min_sdk_version,
                             public=basicsDict['isPublic'])
        Queue.objects.create(priority=priority,
                             analyzer_type='ML',
                             sample_id=sampleEntry,
                             status='idle',
                             bot='',
                             android_version=sampleEntry.android_version,
                             min_sdk_version = sampleEntry.min_sdk_version,
                             public=basicsDict['isPublic'])
        Queue.objects.create(priority=priority,
                             analyzer_type='SAAF',
                             sample_id=sampleEntry,
                             status='idle',
                             bot='',
                             android_version=sampleEntry.android_version,
                             min_sdk_version = sampleEntry.min_sdk_version,
                             public=basicsDict['isPublic'])
        SampleOrigin.objects.create(sample_id=sampleEntry, origin=basicsDict['origin'], download_data='unknown')
        return sampleEntry
    else:
        return basicsDict['error_message']