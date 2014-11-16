#!/usr/bin/python

import sys
import re
import dns.reversename
import dns.resolver
import logging
import socket
from logging.handlers import SysLogHandler

"""
Extracts info from a logline.
\w matches a word
\d matches a digit
a-zA-Z match any alphabetic letter
{1,2} means any digit or letter with 1 or 2 characters "11", "23", "do"
Parenthesis around anything mean that this will be part of a group. "data.group(1), data.group(2), etc"
"""

resolver = dns.resolver.Resolver()
resolver.nameservers = ['127.0.0.1']

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



def extract_log_data(logs):
    data = re.search(r"^(\w+ \d{1,2} \d{1,2}\:\d{1,2}\:\d{1,2}) (\w+) dnsmasq\[(\d+)\]\: query\[(\w+)\] ([a-zA-Z\-\.]+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", logs)
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
 
"""
This will take the arguments from the command line, and put them together as one string
"""
def cmd_args():
    import sys
    if len(sys.argv) == 1:
        print("No arguments given.")
    else:
        sys.argv.pop(0)
        # Since command line arguments are separated by spaces, and thus not included
        # We join the arguments together, and put the spaces back in-between each argument
        return(' '.join(sys.argv))
 
# Get command lines, and make a string out of it.
# This string variable should look something like this:
# Nov 16 15:26:22 cloud dnsmasq[15100]: query[A] m.facebook.com from 192.168.0.138
command_line = cmd_args()
 
# Now that we have a string variable, with the log line, we parse the line into multiple variables.
log_data = extract_log_data(command_line)
 
# Now we check. Did it pass ok?
if log_data != False:
    # If so, we now have a dictionary where we can call each element by name
    print(log_data['host'])
    print(log_data['ip'])

    with open('/var/lib/misc/dnsmasq.leases') as leases:
      for line in leases:
         values = line.split()
         mac = values[1]
         ip = values[2]
         name = values[3]
         if ip == str(log_data['ip']):
          print mac,ip,name
          break

    logger.info("source-address=\""+log_data['ip'] +"\"" + " dns-request=\""+log_data['host']+"\""+" username=\""+mac+"\""+" roles=\""+name+"\""              )


