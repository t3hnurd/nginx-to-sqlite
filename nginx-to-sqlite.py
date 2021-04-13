#!/usr/bin/env python
import gzip
import os
import sys
import re
import sqlite3
import datetime
import calendar

'''
Thank you to hreeder and SegFaultAX for starter regex snippets and strategy reference.
https://gist.github.com/hreeder/f1ffe1408d296ce0591d
https://gist.github.com/SegFaultAX/05e0f76a8dd5dd5d28964585f2b14049
'''

# Use the current working directory
INPUT_DIR = "./"

# SQL statement to create the database table
CREATE_REQUESTS_TABLE = """
create table if not exists requests (
  id integer primary key,
  ip text,
  remoteuser text,
  timestamp text,
  cipher text,
  url text,
  bytessent integer,
  referrer text,
  useragent text,
  status integer,
  method text
);
"""

# SQL statement to insert a record into the database table
INSERT_DATABASE_ROWS = """
insert into requests (
  ip,
  remoteuser,
  timestamp,
  cipher,
  url,
  bytessent,
  referrer,
  useragent,
  status,
  method)
  values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

# TODO
# Modify regex to accept all HTTP request methods, rather than the whitelisted ones
# Add proper CLI argument handling for directory path, output DB, input file(s), etc.
# Deduplicate for loop
# Drop missed lines into error output file

# Regex to process Nginx logs occurring over clear HTTP
lineformat_plain = re.compile(r"""(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remoteuser>[-a-zA-Z0-9@\+\.]+) \[(?P<dateandtime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((?P<method>\"(GET|POST|OPTIONS|HEAD|PUT|DELETE|TRACE|CONNECT|PATCH) )(?P<url>.+)(http\/1\.1")) (?P<statuscode>\d{3}) (?P<bytessent>\d+) (["](?P<refferer>(\-)|(.+))["]) (["](?P<useragent>.+)["])""", re.IGNORECASE)

# Regex to process Nginx logs containing SSL/TLS connection data over HTTPS
lineformat_tls = re.compile(r"""(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - (?P<remoteuser>[-a-zA-Z0-9@\+\.]+) \[(?P<dateandtime>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] (?P<cipher>((TLSv|SSLv)[1-3]\.[0-3]\/[-A-Z0-9]+)) ((?P<method>\"(GET|POST|OPTIONS|HEAD|PUT|DELETE|TRACE|CONNECT|PATCH) )(?P<url>.+)(http\/1\.1")) (?P<statuscode>\d{3}) (?P<bytessent>\d+) (["](?P<refferer>(\-)|(.+))["]) (["](?P<useragent>.+)["])""", re.IGNORECASE)

# Convert Nginx log timestamp into a Unix epoch timestamp
# Recommended for creating usable timeseries data for frontend tools like Grafana
def parse_date(timestamp):
    """Parse the nginx time format into datetime"""
    fmt = '%d/%b/%Y:%H:%M:%S +0000'
    dt = datetime.datetime.strptime(timestamp, fmt)
    return calendar.timegm(dt.timetuple())

if __name__ == "__main__":
    print("Creating database...")
    db = sqlite3.connect('nginx_log.db')
    db.execute(CREATE_REQUESTS_TABLE)
    db.commit()
    
    committed_lines = 0
    missed_rows = 0
    for f in os.listdir(INPUT_DIR):
        db_rows = []
        if f.endswith(".gz"):
            logfile = gzip.open(os.path.join(INPUT_DIR, f))
        elif f.endswith(".log"):
            logfile = open(os.path.join(INPUT_DIR, f))
        else:
            continue
        print("Processing file " + f + "...")

        lines = logfile.readlines()
        for l in lines:
            data = re.search(lineformat_tls, str(l))
            if data: # Process a single Nginx log line
                datadict = data.groupdict()
                ip = datadict["ipaddress"]
                remoteuser = datadict["remoteuser"]
                datetimestring = datadict["dateandtime"]
                cipher = datadict["cipher"]
                url = datadict["url"]
                bytessent = datadict["bytessent"]
                referrer = datadict["refferer"]
                useragent = datadict["useragent"]
                status = datadict["statuscode"]
                method = datadict["method"]
                timestamp = parse_date(datetimestring)
                line = [ip, remoteuser, timestamp, cipher, url, bytessent, referrer, useragent, status, method.strip('"')]
                db_rows.append(line)

                if(len(db_rows) == 500): # Commit 500 row chunks to the database
                    db.executemany(INSERT_DATABASE_ROWS, db_rows)
                    db_rows = []
                    db.commit()
                    committed_lines += 500
                    print(str(committed_lines) + " lines added...", end='\r')
                continue
            data = re.search(lineformat_plain, str(l))
            if data: # Match the HTTP regex pattern if the HTTPS one fails
                datadict = data.groupdict()
                ip = datadict["ipaddress"]
                remoteuser = datadict["remoteuser"]
                datetimestring = datadict["dateandtime"]
                cipher = "None"
                url = datadict["url"]
                bytessent = datadict["bytessent"]
                referrer = datadict["refferer"]
                useragent = datadict["useragent"]
                status = datadict["statuscode"]
                method = datadict["method"]
                timestamp = parse_date(datetimestring)
                line = [ip, remoteuser, timestamp, cipher, url, bytessent, referrer, useragent, status, method.strip('"')]
                db_rows.append(line)

                if(len(db_rows) == 500): # Commit 500 row chunks to the database
                    db.executemany(INSERT_DATABASE_ROWS, db_rows)
                    db_rows = []
                    db.commit()
                    committed_lines += 500
                    print(str(committed_lines) + " lines added...", end='\r')
            else:
                print("Missed row:")
                print(l)
                missed_rows += 1
                continue

        if(len(db_rows) > 0): # Commit any straggling records before opening new file
            committed_lines += len(db_rows)
            db.executemany(INSERT_DATABASE_ROWS, db_rows)
            db_rows = []
            db.commit()
            print(str(committed_lines) + " lines added...")

        logfile.close()
    
    print("Committed rows: " + str(committed_lines))
    print("Missed rows: " + str(missed_rows))
