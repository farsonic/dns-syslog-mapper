#!/usr/bin/python

import sys
import re
import logging
import socket
from logging.handlers import SysLogHandler
from sys import stdin

class ContextFilter(logging.Filter):
  hostname = socket.gethostname()

  def filter(self, record):
    record.hostname = ContextFilter.hostname
    return True

logger = logging.getLogger()
logger.setLevel(logging.INFO)

f = ContextFilter()
logger.addFilter(f)


syslog = SysLogHandler(address=('192.168.0.250', 514))
formatter = logging.Formatter('%(asctime)s %(hostname)s DNS-Tracker %(message)s', datefmt='%Y-%m-%dT%H:%M:%S')
syslog.setFormatter(formatter)
logger.addHandler(syslog)

userinput = sys.stdin.readline()

def extract_log_data(logs):
    data = re.search(r"^(\d{1,4}\-\d{1,2}\-\d{1,2}\D\d{1,2}:\d{1,2}:\d{1,2}.\d{1,6}\D\d{1,2}:\d{1,2}) (\w+) dnsmasq\[(\d+)\]\: query\[(\w+)\] ([a-zA-Z\-\.]+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", logs)
    if data:
        info = {
            'date': data.group(1),
            'cloud': data.group(2),
            'dnsmasq': data.group(3),
            'query': data.group(4),
            'host': data.group(5),
            'ip': data.group(6)
            }
        return info
    # If log is messed up, will return False. This way you can check "if extract_log_data(...) != False: ...
    return False
 
# Accept the data passed from rsyslog $msg and pass for extraction. 
log_data = extract_log_data(userinput)
 
# Validate that the regex passed and has valid data, if so progress with creating a syslog event
if log_data != False:
    with open('/var/lib/misc/dnsmasq.leases') as leases:
      for line in leases:
         values = line.split()
         mac = values[1]
         ip = values[2]
         name = values[3]
         if ip == str(log_data['ip']):
          break
         else: 
          ip = "unknown"
          name = "unknown"
          mac = "unknown"

    logger.info("source-address=\""+log_data['ip'] +"\"" + " dns-request=\""+log_data['host']+"\""+" mac-address=\""+mac+"\""+" client-id=\""+name+"\""              )


