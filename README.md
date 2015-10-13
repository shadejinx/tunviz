# tunviz.py
DNS Tunnel Detection

## Introduction
This application parses a DNS server log entry and looks for signs of DNS Tunnel Activity through the very complicated method of filtering out the crap you don't want and counting the rest. 

## Requirements
TLDextract is required. Get it at: https://github.com/john-kurkowski/tldextract

## Instructions

##### Command-line arguments
```
python tunviz.py [-dfq][-b int][-i input_file] -c config_file

-b int          Set how many seconds between beacons (default:5)
-c filename     Location of the config file (default:default.cfg)  
-d              Enable debug mode (default:False)
-f              Use Addtional Noise Filtering (default:False)
-i filename     Location of the file to parse (default:None)
-q              Quiet Mode, only results output (default:False)
```
##### Example

`python tunviz.py -d -f -b 60 -i log.txt -c default.cfg`

It can also take stdin as an input:

`cat log1.txt log2.txt | python tunviz.py -q -c default.cfg`

## Config File
The config file has 2 types of sections, General and Parser

The General section can configure beacon and addtional filter values, but the command-line argument will override them.

The Parser sections contain the following values:
* **regex**: This is a regular expression that is used to parse a log line into the following fields: date_time, status, query_type and question
* **date_time**: This is an _INT_ representing the regex capture group that contains the date and time
* **date_time_format**: This is the strptime encoded format that the date_time field is in. See http://pubs.opengroup.org/onlinepubs/009695399/functions/strptime.html for more information. *Note: ConfigParser requires '%' symbols to be escaped by another '%'. See default.cfg for an example.*
* **status**: This is an _INT_ representing the regex capture group that contains the status of the DNS Request. (e.g. NOERROR or NXDOMAIN)
* **query_type**: This is an _INT_ representing the regex capture group that contains the type of query. (e.g. A, AAAA, MX, CNAME, etc.)
* **question**: This is an _INT_ representing the regex capture group that contains the FQDN that was requested. In Windows DNS logs, this entry looks like (3)www(6)google(3)com(0). The script can handle this case.
