#!/usr/bin/env python
#
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# SOURCE: https://github.com/atereshkin/abpy/blob/master/abpy.py
# modified by Paul Hofmann
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org>
#
#########################################################################################
#                          Imports  & Global Variables                                  #
#########################################################################################
import re

RE_TOK = re.compile('\W')
MAP_RE = (('\|\|','(//|\.)'),
          ('\^', r'[/\\:+!@#\$^\^&\*\(\)\|]'),
          ('\*', r'.*'))

class RuleSyntaxError(Exception):
    pass

TYPE_OPTS = (('script', 'external scripts loaded via HTML script tag'),
             ('image', 'regular images, typically loaded via HTML img tag'),
             ('stylesheet', 'external CSS stylesheet files'),
             ('object', 'content handled by browser plugins, e.g. Flash or Java'),
             ('xmlhttprequest', 'requests started by the XMLHttpRequest object'),
             ('object-subrequest', 'requests started plugins like Flash'),
             ('subdocument', 'embedded pages, usually included via HTML frames'),
             ('document', 'the page itself (only exception rules can be applied to the page)'),
             ('elemhide', 'for exception rules only, similar to document but only disables element hiding rules on the page rather than all filter rules (Adblock Plus 1.2 and higher required)'),
             ('other', 'types of requests not covered in the list above'))
TYPE_OPT_IDS = [x[0] for x in TYPE_OPTS]
#########################################################################################
#                               Helper Functions                                        #
#########################################################################################
class Rule(object):
    def __init__(self, rule_str):
        self.rule_str = rule_str.strip()
        if '$' in rule_str:
            try:
                self.pattern, self.optstring = rule_str.split('$')
            except ValueError:
                raise RuleSyntaxError()
        else:
            self.pattern = self.rule_str
            self.optstring = ''
        self.regex = self._to_regex()
        opts = self.optstring.split(',')
        self.excluded_elements = []
        self.matched_elements = []
        for o in opts:
            if o.startswith('~') and o[1:] in TYPE_OPT_IDS:
                self.excluded_elements.append(o)
            elif o in TYPE_OPT_IDS:
                self.matched_elements.append(o)
        if self.matched_elements == []:
            self.matched_elements = TYPE_OPT_IDS

    def get_tokens(self):
        return RE_TOK.split(self.pattern)

    def match(self, url, elementtype=None):
        if elementtype:
            if elementtype in self.excluded_elements or\
                    (elementtype not in self.matched_elements and\
                         'other' not in self.matched_elements):
                return False
        return self.regex.search(url)

    def _to_regex(self):
        re_str = re.escape(self.pattern)
        for m in MAP_RE:
            re_str = re_str.replace(*m)
        return re.compile(re_str)
    
    def __unicode__(self):
        return self.rule_str

class Filter(object):
    def __init__(self, f):
        self.index = {}
        for rul in f.xreadlines():
            if rul.startswith('!'): # Comment 
                continue 
            if '##' in rul: # HTML rule
                continue
            try:
                rule = Rule(rul)
            except RuleSyntaxError:
                print 'syntax error in ', rul
            for tok in rule.get_tokens():
                if len(tok) > 2:
                    if tok not in self.index:
                        self.index[tok] = []
                    self.index[tok].append(rule)

    def match(self, url, elementtype=None):
        found = []
        tokens = RE_TOK.split(url)
        for tok in tokens:
            if len(tok) > 2:
                if tok in self.index:
                    for rule in self.index[tok]:
                        if rule.match(url, elementtype=elementtype):
                            found.append(unicode(rule))
        return found