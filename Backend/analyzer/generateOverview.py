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
from analyzer.models import Overview, Reports
import json
#########################################################################################
#                                    Functions                                          #
#########################################################################################
def gatherDataStatic(sampleID):
    iNetCommunication = ''
    calendarAccess = ''
    contactAccess = ''
    pictureAccess = ''
    accountAccess = ''
    loadLib = ''
    microphoneAccess = ''
    simAccess = ''
    useCamera = ''
    useGPS = ''
    modifySettings = ''
    deviceIdentifiersAccess = ''
    usePhone = ''
    useCrypto = ''
    useDB = ''
    smsAccess = ''
    sendSMS = ''
    installApps = ''
    disableScreenLock = ''
    useStorage = ''
    useNetworkTriangulation = ''
    # TODO: automatically choose the ID of the correct analyzer
    found_entries = Reports.objects.filter(sample_id_id__exact=sampleID, analyzer_id_id__exact='3')
    jsonFile = found_entries.values_list('filesystem_position')[0][0]
    jsonData = json.loads(open(jsonFile, 'r').read())
    # Q01 -- Does the app try to access the local address book:
    try:
        for node in jsonData['app_permissions']:
            if node == 'android.permission.READ_CONTACTS':
                contactAccess += node + '|'
            elif node == 'android.permission.WRITE_CONTACTS':
                contactAccess += node + '|'
            else:
                continue
        if contactAccess == '':
            contactAccess = 'no'
    except:
        contactAccess = 'error'
    # Q02 -- Does the app try to access the local calendar:
    try:
        for node in jsonData['app_permissions']:
            if node == 'android.permission.READ_CALENDAR':
                calendarAccess += node + '|'
            elif node == 'android.permission.WRITE_CALENDAR':
                calendarAccess += node + '|'
            else:
                continue
        if calendarAccess == '':
            calendarAccess = 'no'
    except:
        calendarAccess = 'error'
    # Q03 -- Does the app try to access stored pictures:
    try:
        for node in jsonData['providers']:
            if node == 'android.provider.MediaStore.Images.Media.INTERNAL_CONTENT_URI':
                pictureAccess += node + '|'
            elif node == 'android.provider.MediaStore.Images.Media.EXTERNAL_CONTENT_URI':
                pictureAccess += node + '|'
            else:
                continue
        if pictureAccess == '':
            pictureAccess = 'no'
    except:
        pictureAccess = 'error'
    # Q04 -- Does the app try to access configured accounts:
    try:
        for node in jsonData['app_permissions']:
            if node == 'android.permission.GET_ACCOUNTS':
                accountAccess += node + '|'
            elif node == 'android.permission.USE_CREDENTIALS':
                accountAccess += node + '|'
            elif node == 'android.permission.MANAGE_ACCOUNTS':
                accountAccess += node + '|'
            elif node == 'android.permission.ACCOUNT_MANAGER':
                accountAccess += node + '|'
            elif node == 'android.permission.AUTHENTICATE_ACCOUNTS':
                accountAccess += node + '|'
            else:
                continue
        if accountAccess == '':
            accountAccess = 'no'
    except:
        accountAccess = 'error'
    # Q05 -- Does the app try to access the local SMS or MMS messages:
    try:
        for node in jsonData['app_permissions']:
            if node == 'android.permission.READ_SMS':
                smsAccess += node + '|'
            else:
                continue
        if smsAccess == '':
            smsAccess = 'no'
    except:
        smsAccess = 'error'
    # Q06 -- Does the app try to access device identifiers:
    try:
        for node in jsonData['api_calls']:
            if node == 'getDeviceId':
                deviceIdentifiersAccess += node + '|'
            elif 'Access Device Info' in node:
                deviceIdentifiersAccess += node + '|'
            else:
                continue
        if deviceIdentifiersAccess == '':
            deviceIdentifiersAccess = 'no'
    except:
        deviceIdentifiersAccess = 'error'
    # Q07 -- Does the app try to access SIM card identifiers:
    try:
        for node in jsonData['api_calls']:
            if node == 'getSimCountryIso':
                simAccess += node + '|'
            elif node == 'getSubscriberId':
                simAccess += node + '|'
            else:
                continue
        if simAccess == '':
            simAccess = 'no'
    except:
        simAccess = 'error'
    # Q08 -- Does the app use crypto:
    try:
        for node in jsonData['api_calls']:
            if 'Cipher' in node:
                useCrypto += node + '|'
            else:
                continue
        if useCrypto == '':
            useCrypto = 'no'
    except:
        useCrypto = 'error'
    # Q09 -- Does the app load external libraries:
    try:
        for node in jsonData['api_calls']:
            if 'Loading of external Libraries' in node:
                loadLib += node + '|'
            else:
                continue
        if loadLib == '':
            loadLib = 'no'
    except:
        loadLib = 'error'
    # Q10 -- Does the app try to modify device settings:
    try:
        for node in jsonData['app_permissions']:
            if node == 'android.permission.MODIFY_AUDIO_SETTINGS':
                modifySettings += node + '|'
            elif node == 'android.permission.WRITE_APN_SETTINGS':
                modifySettings += node + '|'
            elif node == 'android.permission.WRITE_SECURE_SETTINGS':
                modifySettings += node + '|'
            elif node == 'android.permission.WRITE_SETTINGS':
                modifySettings += node + '|'
            elif node == 'android.permission.WRITE_SYNC_SETTINGS':
                modifySettings += node + '|'
            elif node == 'android.permission.CHANGE_WIFI_STATE':
                modifySettings += node + '|'
            else:
                continue
        if modifySettings == '':
            modifySettings = 'no'
    except:
        modifySettings = 'error'
    # Q11 -- Does the app try to install additional apps:
    try:
        for node in jsonData['app_permissions']:
            if node == 'android.permission.INSTALL_PACKAGES':
                installApps += node + '|'
            else:
                continue
        if installApps == '':
            installApps = 'no'
    except:
        installApps = 'error'
    # Q12 -- Does the app try to disable the screen lock:
    try:
        for node in jsonData['app_permissions']:
            if node == 'android.permission.WAKE_LOCK':
                disableScreenLock += node + '|'
            elif node == 'android.permission.DISABLE_KEYGUARD':
                disableScreenLock += node + '|'
            else:
                continue
        if disableScreenLock == '':
            disableScreenLock = 'no'
    except:
        disableScreenLock = 'error'
    # Q13 -- Does the app embed ad networks:
    q13 = 'n/a'
    # Q14 -- Does the app try to use the camera:
    try:
        for node in jsonData['features']:
            if 'android.hardware.camera' in node:
                useCamera += node + '|'
            else:
                continue
        if useCamera == '':
            useCamera = 'no'
    except:
        useCamera = 'error'
    # Q15 -- Does the app try to use the microphone:
    try:
        for node in jsonData['features']:
            if node == 'android.hardware.microphone':
                microphoneAccess += node + '|'
            else:
                continue
        for node in jsonData['api_calls']:
            if 'Possible Audio Recording' in node:
                microphoneAccess += node + '|'
            else:
                continue
        for node in jsonData['app_permissions']:
            if node == 'android.permission.RECORD_AUDIO':
                microphoneAccess += node + '|'
            else:
                continue
        if microphoneAccess == '':
            microphoneAccess = 'no'
    except:
        microphoneAccess = 'error'
    # Q16 -- Does the app try to locate the device using the GPS sensor:
    try:
        for node in jsonData['features']:
            if node == 'android.hardware.location.gps':
                useGPS += node + '|'
            else:
                continue
        for node in jsonData['app_permissions']:
            if node == 'android.permission.ACCESS_FINE_LOCATION':
                useGPS += node + '|'
            else:
                continue
        if useGPS == '':
            useGPS = 'no'
    except:
        useGPS = 'error'
    # Q17 -- Does the app try to locate the device using network triangulation:
    try:
        for node in jsonData['features']:
            if node == 'android.hardware.location.network':
                useNetworkTriangulation += node + '|'
            else:
                continue
        for node in jsonData['api_calls']:
            if node == 'getCellLocation':
                useNetworkTriangulation += node + '|'
            else:
                continue
        for node in jsonData['app_permissions']:
            if node == 'android.permission.ACCESS_COARSE_LOCATION':
                useNetworkTriangulation += node + '|'
            else:
                continue
        if useNetworkTriangulation == '':
            useNetworkTriangulation = 'no'
    except:
        useNetworkTriangulation = 'error'
    # Q18 -- Does the app communicate with the Internet:
    try:
        for node in jsonData['api_calls']:
            if node == 'HTTP_POST':
                iNetCommunication += node + '|'
            elif node == 'HTTP_GET':
                iNetCommunication += node + '|'
            elif 'HttpPost' in node:
                iNetCommunication += node + '|'
            else:
                continue
        for node in jsonData['app_permissions']:
            if node == 'android.permission.INTERNET':
                iNetCommunication += node + '|'
            else:
                continue
        if iNetCommunication == '':
            iNetCommunication = 'no'
    except:
        iNetCommunication = 'error'
    # Q19 -- Does the app use cloud services:
    q19 = 'n/a'
    # Q20 -- Does the app try to send SMS messages:
    try:
        for node in jsonData['app_permissions']:
            if node == 'android.permission.WRITE_SMS':
                sendSMS += node + '|'
            elif node == 'android.permission.SEND_SMS':
                sendSMS += node + '|'
            else:
                continue
        if sendSMS == '':
            sendSMS = 'no'
    except:
        sendSMS = 'error'
    # Q21 -- Does the app try to start a phone call:
    try:
        for node in jsonData['app_permissions']:
            if node == 'android.permission.CALL_PHONE':
                usePhone += node + '|'
            elif node == 'android.permission.CALL_PRIVILEGED':
                usePhone += node + '|'
            else:
                continue
        if usePhone == '':
            usePhone = 'no'
    except:
        usePhone = 'error'
    # Q22 -- Does the app try to open local ports:
    q22 = 'n/a'
    # Q23 -- Does the app use local databases to store data:
    try:
        for node in jsonData['api_calls']:
            if node == 'execSQL':
                useDB += node + '|'
            elif node == 'Use of local SQLite Database':
                useDB += node + '|'
            else:
                continue
        if useDB == '':
            useDB = 'no'
    except:
        useDB = 'error'
    # Q24 -- Does the app use local storage (like SD card):
    try:
        for node in jsonData['app_permissions']:
            if node == 'android.permission.WRITE_EXTERNAL_STORAGE':
                useStorage += node + '|'
            elif node == 'android.permission.MOUNT_UNMOUNT_FILESYSTEMS':
                useStorage += node + '|'
            elif node == 'android.permission.MOUNT_FORMAT_FILESYSTEMS':
                useStorage += node + '|'
            else:
                continue
        if useStorage == '':
            useStorage = 'no'
    except:
        useStorage = 'error'
    # write to database
    Overview.objects.get_or_create(sample_id_id = sampleID,
                                   q01=contactAccess,q02=calendarAccess,q03=pictureAccess,q04=accountAccess,q05=smsAccess,
                                   q06=deviceIdentifiersAccess,q07=simAccess,q08=useCrypto,q09=loadLib,q10=modifySettings,
                                   q11=installApps,q12=disableScreenLock,q13=q13,q14=useCamera,q15=microphoneAccess,
                                   q16=useGPS,q17=useNetworkTriangulation,q18=iNetCommunication,q19=q19,q20=sendSMS,
                                   q21=usePhone,q22=q22,q23=useDB,q24=useStorage)

#TODO: needs to be implemented !!
def gatherDataDynamic(sampleID):
    return True
    '''
    iNetCommunication = ''
    calendarAccess = ''
    contactAccess = ''
    pictureAccess = ''
    accountAccess = ''
    loadLib = ''
    microphoneAccess = ''
    simAccess = ''
    useCamera = ''
    useGPS = ''
    modifySettings = ''
    deviceIdentifiersAccess = ''
    usePhone = ''
    useCrypto = ''
    useDB = ''
    smsAccess = ''
    sendSMS = ''
    installApps = ''
    disableScreenLock = ''
    useStorage = ''
    useNetworkTriangulation = ''    
    found_entries = Reports.objects.filter(id__exact=sampleID)
    jsonFile = found_entries.values_list('filesystem_position')[0][0]
    droidbox_json = json.loads(open(jsonFile).read())
    #jsonData = json.loads(open(jsonFile, 'r').read())
    
    # Q01 -- Does the app try to access the local address book:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q02 -- Does the app try to access the local calendar:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q03 -- Does the app try to access stored pictures:
    
    # faccesses -> is picture
    # cf. https://docs.python.org/2/library/imghdr.html
    try:
        if pictureAccess == '':
            pictureAccess = 'no'
    except:
        pictureAccess = 'error'
        
    # Q04 -- Does the app try to access configured accounts:
    ### ???? ###
    try:
        if accountAccess == '':
            accountAccess = 'no'
    except:
        accountAccess = 'error'
    # Q05 -- Does the app try to access the local SMS or MMS messages:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q06 -- Does the app try to access device identifiers:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q07 -- Does the app try to access SIM card identifiers:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q08 -- Does the app use crypto:
    
    # crypto usage
    try:
        if useCrypto == '':
            useCrypto = 'no'
    except:
        useCrypto = 'error'
    # Q09 -- Does the app load external libraries:
    try:
        if loadLib == '':
            loadLib = 'no'
    except:
        loadLib = 'error'
    # Q10 -- Does the app try to modify device settings:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q11 -- Does the app try to install additional apps:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q12 -- Does the app try to disable the screen lock:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q13 -- Does the app embed ad networks:
    q13 = 'n/a'
    # Q14 -- Does the app try to use the camera:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q15 -- Does the app try to use the microphone:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q16 -- Does the app try to locate the device using the GPS sensor:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q17 -- Does the app try to locate the device using network triangulation:
    # - STATIC ANALYSIS IS SUFFICIENT - 
    # Q18 -- Does the app communicate with the Internet:
    
    #get_request_data  & PCAP
    try:
        if iNetCommunication == '':
            iNetCommunication = 'no'
    except:
        iNetCommunication = 'error'
        
    # Q19 -- Does the app use cloud services:
    q19 = 'n/a'
    # Q20 -- Does the app try to send SMS messages:
    
    # get_sent_sms
    try:
        if sendSMS == '':
            sendSMS = 'no'
    except:
        sendSMS = 'error'
        
        
    # Q21 -- Does the app try to start a phone call:
    
    #get_phonecalls
    try:
        if usePhone == '':
            usePhone = 'no'
    except:
        usePhone = 'error'
    # Q22 -- Does the app try to open local ports:
    
    #netstat
    q22 = 'n/a'
    # Q23 -- Does the app use local databases to store data:
    
    # sqlite_parse
    try:
        if useDB == '':
            useDB = 'no'
    except:
        useDB = 'error'
        
    # Q24 -- Does the app use local storage (like SD card):
    
    # get_file_accesses
    try:
        if useStorage == '':
            useStorage = 'no'
    except:
        useStorage = 'error'
    # write to database
    
    # TODO: Avoid override of static analysis data
    Overview.objects.get_or_create(sample_id_id = sampleID,
                                   q01=contactAccess,q02=calendarAccess,q03=pictureAccess,q04=accountAccess,q05=smsAccess,
                                   q06=deviceIdentifiersAccess,q07=simAccess,q08=useCrypto,q09=loadLib,q10=modifySettings,
                                   q11=installApps,q12=disableScreenLock,q13=q13,q14=useCamera,q15=microphoneAccess,
                                   q16=useGPS,q17=useNetworkTriangulation,q18=iNetCommunication,q19=q19,q20=sendSMS,
                                   q21=usePhone,q22=q22,q23=useDB,q24=useStorage)
   '''