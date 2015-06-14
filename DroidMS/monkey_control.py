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
import sys, time, re, subprocess
import settings
# Imports the monkeyrunner modules used by this program
sys.path.append(settings.MONKEYDIR)
from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice
# global variables
CC = ''.join(map(unichr, range(0,32) + range(127,160)))
#########################################################################################
#                                    Functions                                          #
#########################################################################################

def getActivities(sampleFile):
    activities = []
    manifest = subprocess.Popen([settings.AAPT, 'dump', 'badging', sampleFile],
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    manifest = manifest.communicate()[0].split("\n")
    for line in manifest:
        if "activity" in line:
            try:
                activity = line.split("'")[1].split(".")[-1]
                activity = re.compile('[%s]' % re.escape(CC)).sub('', activity)
                activity = "." + activity
                if activity not in activities:
                    activities.append(activity)
                else:
                    continue
            except:
                continue
        else:
            continue
    manifest = subprocess.Popen([settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    manifest = manifest.communicate()[0].split("\n")
    for i,line in enumerate(manifest):
        if "activity" in line:
            try:
                nextLine = manifest[i+2].split("=")[1].split('"')[1]
                nextLine = re.compile('[%s]' % re.escape(CC)).sub('', nextLine)
                if nextLine not in activities:
                    activities.append(nextLine)
                else:
                    continue
            except:
                continue
        else:
            continue
    return activities

def connectDevice():
    print "----> waiting for device"
    device = MonkeyRunner.waitForConnection(5, 'emulator-5554')
    return device

def installApp(device, app, count):
    print "----> installing \033[0;34m" + app + "\033[m"
    status = "untested"
    if count < 4:
        install = subprocess.Popen([settings.ADB, 'install', app],
                                   stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        install = install.communicate()[0]
        if install.find('Success') == -1:
                if install.find('INSTALL_FAILED_ALREADY_EXISTS') != -1:
                    print "----> application already installed!"
                elif install.find('Is the system running?') != -1:
                    print "----> It seems that the system is not running! Waiting 20sec and then installing again...."
                    time.sleep(20)
                    count += 1
                    installApp(device, app, count)
                else:
                    print "----> Error occurred! Waiting 20sec and then installing again...."
                    print install
                    time.sleep(20)
                    count += 1
                    installApp(device, app, count)
        else:
            print "----> installation of \033[0;34m" + app + "\033[m was successful"
            status = "success"
    else:
            print "----> installation of \033[0;34m" + app + "\033[m failed !!!"
            status = "fail"
    print "----> installation status: \033[0;34m" + status + "\033[m"
    return status
    
def uninstallApp(device, package):
    print "----> uninstalling \033[0;34m" + package + "\033[m"
    device.removePackage(package)
    
def startActivity(device, package, activity):
    runComponent = package + '/' + activity
    device.startActivity(component=runComponent)
    
def useMonkey(package):
    print "----> using monkey within \033[0;34m" + package + "\033[m"
    usingApp = subprocess.Popen([settings.ADB, 'shell', 'monkey', '--throttle 100', '-p',
                                 package, '-c android.intent.category.LAUNCHER --pct-syskeys 5 --pct-appswitch 10 '
                                          '--pct-motion 10 --pct-anyevent 0 100'])
    usingApp.wait()

def takeScreenshot(device):
    print "----> taking screenshot"
    result = device.takeSnapshot()
    result.writeToFile(settings.TMPDIR + "screenshot.png",'png')

#########################################################################################
#                                  MAIN PROGRAMM                                        #
#########################################################################################
def main(sampleFile, package, workingDir):
    activity = getActivities(sampleFile)
    device = connectDevice()
    status = installApp(device, sampleFile, 0)
    if status == "success":
        time.sleep(20)
        for element in activity:
            if element.startswith("."):
                active = package + element
                print "start activity :" + active
                startActivity(device, package, active)
                time.sleep(20)
                takeScreenshot(device)
                time.sleep(20)
                useMonkey(package)
                break
            else:
                continue
    else:
        sys.exit(3)

if __name__ == '__main__':
    sampleFile = sys.argv[1]
    package = sys.argv[2]
    workingDir = sys.argv[3]
    main(sampleFile, package, workingDir)