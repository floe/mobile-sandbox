#!/usr/bin/env python
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2013, Mobile-Sandbox
# Author: Daniel Arp (daniel.arp@informatik.uni-goettingen.de)
# Author: Michael Spreitzenbarth (research@spreitzenbarth.de)
# Author: Paul Hofmann
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
import urlparse, urllib
import json
import string
#########################################################################################
#                                    Functions                                          #
#########################################################################################
class ReportLoader():
    '''
        class to load json report files of mobile sandbox
    '''
    
    __static_features_singletons = ['sha256',
                                    'package_name',
                                    'apk_name',
                                    'sdk_version',
                                    'ssdeep',
                                    'md5']
    
    __static_features = [ 'features',
                        'intents',
                        'providers',
                        'networks',
                        'api_calls',
                        'urls',
                        'activities',
                        'api_permissions',
                        'app_permissions',
                        'interesting_calls',
                        's_and_r',
                        'included_files'] + __static_features_singletons
    __ignore_feature_type = [ 'file' ]

    def __init__(self, report_file):
        self.__report_file = report_file
        self.__app_features = list()
        self.__process_features = { 'url' : self.__process_url,
                                   'api_call' : self.__process_api_calls }

    def get_features(self):
        '''
            returns list of application features
            format: 'feature_type::feature'
        '''
        report_json = json.loads(open(self.__report_file).read())
        
        # clear list of features
        self.__app_features[:] = [] 
        
        for feature in report_json:
            
            if self.__is_static_feature(feature):
                self.__process_static_feature(feature, report_json[feature])
            # TODO: insert dynamic features and use detected_ad_network feature
            else:
                if (feature not in ['#text', 'info']) and (len(report_json[feature]) != 0):
                    continue

        return self.__app_features
        

    def __is_static_feature(self, feature):
        '''
            Is the given feature a valid and static feature?
        '''
        return (feature in ReportLoader.__static_features)
    

    def __process_static_feature(self, feature, feature_data):
        '''
            Processes a given feature. If the given feature is valid and unignored, it'll be added to the features list.
        '''
        entry_type = self.__get_type(feature)
        if feature not in self.__ignore_feature_type:
            self.__process_feature_data(entry_type, feature_data)


    def __get_type(self, feature):
        '''
            Returns type name of the given feature.
        '''
        exceptions = { 'activities' : 'activity',
                    'services_receivers' : 'service_receiver',
                    's_and_r' : 's_and_r' }
        if feature in self.__static_features_singletons:
            return feature
        elif feature not in exceptions:
            # cut 's' (permissions -> permission)
            return feature[:len(feature) - 1]
        else:
            return exceptions[feature]
            

    def __process_feature_data(self, entry_type, feature_data):
        '''
            Adds given feature data to the features list.
        '''
        if isinstance(feature_data, basestring):
            self.__process_single_item(entry_type, feature_data)
        else:
            for child in feature_data:
                self.__process_single_item(entry_type, child)

        
    def __process_single_item(self, entry_type, item):
        '''
            Adds the given item to the features list.
        '''
        if entry_type in self.__process_features:
            item = self.__process_features[entry_type](item)
        if not self.__is_only_whitespace(item):
            feature = '{}::{}'.format(entry_type, item)
            self.__app_features.append(feature)
    
    
    def __process_api_calls(self, api_call):
        '''
            return a merged output of the api call and the corresponding permission.
            (separated by ":")
        '''
        actCall = api_call[0].strip()
        perm = api_call[1].strip()
        return "%s : %s" % (actCall, perm)


    def __process_url(self, url):
        '''
            return hostname of extracted url.
        '''
        safe = '\x3A\x2F\x24\x25\x22\x26\x28\x29\x2A'
        safe += '\x2B\x3F\x5B\x5C\x5D\x5E\x2C\x3C\x3E'
        url = urllib.quote(url, safe)
        url = url.replace('%25', '%')
        # get hostname
        try:
            hostname = urlparse.urlparse(url).netloc.split(':')[0]
        except:
            hostname = ''
        # check if hostname is valid
        invalid_names = ['', ' ', '%s', 'TYPE', ':', '.', '__NO_MATCHING_AD__']
        if hostname in invalid_names:
            hostname = ''
        return hostname
    
    
    def __is_only_whitespace(self, theStr):
        '''
            returns true if every single character in the given string is whitespace.
            Otherwise it's false.
        '''
        for c in theStr:
            if c not in string.whitespace:
                return False
        return True


class UnknownJSONPropertyException(Exception):
    def __init__(self, report_file, key_name):
        self.__report_file = report_file
        self.__key_name = key_name
    def __str__(self):
        msg = 'Unknown JSON property in {} with key {}'
        exception_str = msg.format(self.__report_file, self.__key_name)
        return exception_str