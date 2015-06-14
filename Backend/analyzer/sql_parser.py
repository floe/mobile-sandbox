#!/usr/bin/env python
#
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
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
#                       This is only a provisional implementation                       #
#########################################################################################
# TODO: Expand this stub to a valid SQL parser.
# problem: python-sqlparse isn't suitable
# - cf. https://code.google.com/p/python-sqlparse/issues/detail?id=29
#
# Fundamentals that are missing:
# - Table layout (parse columns)
# - Certain query types (INSERT, UPDATE, ALTER,...)

CREATE_TABLE = "CREATE TABLE".split()
CREATE_TABLE_LEN = len(CREATE_TABLE)
CREATE_TABLE_IF_NOT_EXISTS = "CREATE TABLE IF NOT EXISTS".split()
CREATE_TABLE_IF_NOT_EXISTS_LEN = len(CREATE_TABLE_IF_NOT_EXISTS)

def list_starts_with(the_list, starts_with_list, ignore_case=False):
    for i in range(len(starts_with_list)):
        to_compare = (the_list[i].lower(), starts_with_list[i].lower()) if ignore_case else (list[i], starts_with_list[i])
        if to_compare[0] != to_compare[1]:
            return False
    return True

def index_in_list(item, the_list, ignore_case=False):
    item_search = item.lower() if ignore_case else item
    for i in range(len(the_list)):
        item_cmp = the_list[i].lower() if ignore_case else list[i]
        if item_search == item_cmp:
            return i
    return -1
        
def get_table_name_from_query(query):
    table_name = None
    query = query.strip()
    query_list = query.split()
    if list_starts_with(query_list, CREATE_TABLE, ignore_case=True):
        if list_starts_with(query_list, CREATE_TABLE_IF_NOT_EXISTS, ignore_case=True):
            split_idx = CREATE_TABLE_IF_NOT_EXISTS_LEN
        else:
            split_idx = CREATE_TABLE_LEN
        table_name = query_list[split_idx]
    elif query_list[0].lower() == "select":
        from_idx = index_in_list("from", query_list, ignore_case=True)
        if from_idx != -1:
            table_name = query_list[from_idx+1]
    return table_name