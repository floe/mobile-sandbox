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
# MobileSandbox Authentication Parameters
MSURL = ''	                        						            # URL of the Mobile-Sandbox backend
MSAPIFORMAT = 'json'
MSAPIUSER = ''			                                                # API user name
MSAPIKEY = ''       										            # API key for the aforementioned user
# important files and folders
MONKEYDIR = '' 												            # location of the monkey jar file
TMPDIR = '/tmp/analysis/'
AAPT = ''               												# location of the aapt binary
ADB = ''                 												# location of the adb binary
DROIDBOXDIR = './droidbox/'
DROIDBOXINITIALDIR = './droidbox_initial/'
BOTDIR = './'
EMULATORPORT = '5554'                                                   # port the emulator should listen on
# usage data
CALLS = ['call:+11234567890',
         'accept:+11234567890',
         'cancel:+11234567890',
         'accept+11234567890']                                          # list of incoming calls
SMS = ['send +11234567890 Are you evil?',
       'send +11234567890 Hi there, this is just a test!']              # list of incoming SMS messages
GPS = ['28.411629 119.054553',
       '28.411800 119.055555',
       '28.413110 119.055631',
       '28.413210 119.056411']                                          # list of GPS data for movement profile