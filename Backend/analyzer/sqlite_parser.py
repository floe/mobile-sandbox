#!/usr/bin/env python
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
#                          Imports  & Global Variables                                  #
#########################################################################################
import os.path
import sqlite3

SQL_GET_TABLES = "SELECT name,sql FROM sqlite_master WHERE type='table'"
SQL_TABLE_DETAILS = "PRAGMA table_info('%s')"

# cf. http://www.sqlite.org/fileformat.html#database_header
SQLITE_FILE_HEADER_SIZE = 100
SQLITE_FILE_MAGIC_STRING = 'SQLite format 3\000'
SQLITE_FILE_MAGIC_STRING_LENGTH = len(SQLITE_FILE_MAGIC_STRING)

VALID_SQLITE_DB = 0
NO_SQLITE_DB = 1
UNREADABLE_SQLITE_DB = 2
#########################################################################################
#                               Helper Functions                                        #
#########################################################################################
def is_sqlite3(filename):
    
    if not os.path.isfile(filename):
        return False
    if os.path.getsize(filename) < SQLITE_FILE_HEADER_SIZE:
        return False
    else:
        fd = open(filename, 'rb')
        header = fd.read(SQLITE_FILE_HEADER_SIZE)
        fd.close()
    
        if header[0:SQLITE_FILE_MAGIC_STRING_LENGTH] == SQLITE_FILE_MAGIC_STRING:
            return True
        else:
            return False
    
        
def get_db_info(filename, withCols):
    
    conn = None
    table_infos = []

    try:
        conn = sqlite3.connect(filename)
        
        outer_cursor = conn.execute(SQL_GET_TABLES)
        for row in outer_cursor:
            tablename = row[0]
            create_sql = row[1]

            if withCols:
                cols = []
                # Common binding (prepared statements) doesn't work with PRAGMA. But the data source is trustworthy.
                inner_cursor = conn.execute(SQL_TABLE_DETAILS % tablename)
                
                for col_desc in inner_cursor:
                    cols.append({
                                 'cid' : col_desc[0],
                                 'name' : col_desc[1],
                                 'type' : col_desc[2],
                                 'not_null': False if col_desc[3] == 0 else True,
                                 'default_value' : col_desc[4],
                                 'primary_key' : False if col_desc[5] == 0 else True,
                                 })
                    
                table_infos.append({
                                    'name' : tablename,
                                    'create_sql' : create_sql,
                                    'columns' : cols
                                    })
            else:
                table_infos.append({
                                    'name' : tablename,
                                    'create_sql' : create_sql
                                    })
                
        return table_infos
        
    except sqlite3.Error:
        return None
    
    finally:
        conn.close()
        
#########################################################################################
#                                Main Functions                                         #
#########################################################################################
def process_file(filename, withCols=True):
    
    if not is_sqlite3(filename):
        return (NO_SQLITE_DB, None)
    
    db_info = get_db_info(filename, withCols)
    
    if db_info is None:
        return (UNREADABLE_SQLITE_DB, None)
    else:
        return (VALID_SQLITE_DB, db_info)
    
# FUTURE: def process_all_files(file_list, withCols=True):
def process_all_files(dirname, withCols=True):
    files = os.listdir(dirname)
    res = dict()
    for fl in files:
        print os.path.join(dirname, fl)
        res[fl] = process_file(os.path.join(dirname, fl), withCols)
    return res
    
def get_columns_as_html(cols):
    res = '<table class="zebra-striped">'
    res += '''
    <thead>
                <tr>
                    <th class="blue">ID</th>
                    <th class="blue">Table</th>
                    <th class="blue">Type</th>
                    <th class="blue">NOT NULL</th>
                    <th class="blue">Primary</th>
                    <th class="blue">Default</th>
                </tr>
    </thead>
        '''
    for col in cols:
        primary_key = "TRUE" if col['primary_key'] else "FALSE"
        not_null = "TRUE" if col['not_null'] else "FALSE"
        default_value = "NULL" if col['default_value'] is None else col['default_value']
        res += "<tr><td>%i</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" \
        % (col['cid'], col['name'], col['type'], not_null, primary_key, default_value)
    res += "</table>"
    return res    

    
    
    