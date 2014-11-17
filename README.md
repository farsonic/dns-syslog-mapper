DNS-SYSLOG-Mapper   
=================
This script is intended to be used in a closed environemnt where the network is using DNSMASQ for both DCHP address assignment and DNS relay fuctions. DNSMASQ allocates IP addresses and maintains an ongoing lease file that contails the users MAC address, assigned IP address and client-identifer if known. 

When DNSMASQ receives a DNS lookup request from a client it processes the request and returns the IP address to the client. With debugging enabled DNSMASQ will log all DNS requests along with the IP address of the user that has made the request. This script is intended to take the DNS request and process this into a new SYSLOG event (for forwarding to a SIEM) that will contain the following information

* MAC Address of the user 
* Assigned IP address
* Client Identifier (if know, otherwise *)
* Requested hostname for resolution 

The following event is a typical example from DNSMASQ that would be processed 

  2014-11-17T10:57:28.242340+10:00 cloud dnsmasq[15100]: query[A] www-domain.com from 192.168.0.135

The script takes this event in parses the DNSMASQ leases file and generates a new SYSLOG event that would appear as follows

  2014-11-17T13:18:29 cloud DNS-Tracker source-address="192.168.0.135" dns-request="www-domain.com" mac-address="aa:aa:aa:aa:aa:aa" client-id="client-name" 


DNSMASQ Configuration
=====================
DNSMASQ by default doesn't log all requests. To enable this functionality place the following configuration option in your /etc/dnsmasq.conf file
```
log-queries
```
RSYSLOG Configuration
=====================
RSYSLOG can process individual lines/events as they are logged. For this requirement RSYSLOG will monitor events for any line matching query[A] and pass to the script for processing and SYSLOG generation. Place the following entry into /etc/rsyslog.conf and restart rsyslog. 

```
module(load="omprog")

if $msg contains "query[A]" then 
    action(type="omprog"
           binary="/home/fprowse/git/mac-to-dns-logger/readline.py")
```



    

