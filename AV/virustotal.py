#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Author: Michael Spreitzenbarth (research@spreitzenbarth.de)
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
#                                      Imports                                          #
#########################################################################################
import simplejson, urllib, urllib2, functools
#########################################################################################
#                                     Functions                                         #
#########################################################################################
try:
    import posthandler
    post_opener = urllib2.build_opener(posthandler.MultipartPostHandler)
except ImportError:
    posthandler = None

class ModuleNotFound(Exception):
    ''' Module has not been found '''

class VirusTotalAPI(object):
    api_url = "http://www.virustotal.com/api/"
    api_methods = ["get_file_report",
                   "get_url_report",
                   "scan_url",
                   "make_comment"]  # Generic dynamic property methods (_call_api)
    special_methods = ["scan_file"] # Methods with their own function
    
    def __init__(self, api_key):
        self.api_key = api_key
        for method in self.api_methods:
            setattr(self, method, functools.partial(self._call_api,method,key=self.api_key))
        for smethod in self.special_methods:
            setattr(self, smethod, functools.partial(getattr(self,"_special_"+smethod),key=self.api_key))
    
    def _call_api(self, function, **kwargs):
        url = self.api_url + function + ".json"
        data = urllib.urlencode(kwargs)
        req = urllib2.Request(url,data)
        returned = urllib2.urlopen(req).read()
        return simplejson.loads(returned)
    
    def _special_scan_file(self, **kwargs):
        if not posthandler:
            raise ModuleNotFound("posthandler module needed to submit files")
        json = post_opener.open(self.api_url + "scan_file.json",kwargs).read()
        return simplejson.loads(json)