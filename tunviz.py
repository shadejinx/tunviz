#!/usr/bin/python

import re
import datetime
import tldextract
import hashlib
import sys
import getopt
from ConfigParser import SafeConfigParser

__author__ = "shadejinx"
__project__ = "tunviz"
__version__ = "0.5"


def messenger(sev, message):
    time = str(datetime.datetime.now())[:19]
    if sev == 0:
        print time + " [INFO  ]: " + message
    elif sev == 1:
        print time + " [WARN  ]: " + message
    elif sev == 2:
        print time + " [ERROR ]: " + message
    elif sev == 3:
        print time + " [DEBUG ]: " + message
    elif sev == 4:
        print time + " [OUTPUT]: " + message
    return


def process_command_line(argv):

    settings = {}
    settings["additional_filters"] = False
    settings["beacon"] = 5
    settings["config_file"] = ''
    settings["debug"] = False
    settings["input_file"] = ''
    settings["quiet"] = False

    try:
        opts, args = getopt.getopt(argv, "hdfqc:b:i:", ["debug", "additional_filters", "quiet"])
    except getopt.GetoptError:
        messenger(2, "tunviz-" + __version__ + ".py [-cdfq][-b <beacon>][-c <config_file>] -i <inputfile>")
        messenger(2, "Run aborted")
        return 0

    for opt, arg in opts:
        if opt == "-h":
            messenger(0, "tunviz-" + __version__ + ".py [-cdfq][-b <beacon>][-c <config_file>] -i <inputfile>")
            return 0
        elif opt == "-d":
            settings["debug"] = True
        elif opt == "-i":
            settings["input_file"] = arg
        elif opt == "-b":
            settings["beacon"] = int(arg)
        elif opt == "-f":
            settings["additional_filter"] = True
        elif opt == "-q":
            settings["quiet"] = True
        elif opt == "-c":
            settings["config_file"] = arg

    return settings

def read_config_file(settings):

    parsers = {}
    config_options = SafeConfigParser()

    try:
        config_options.read(settings["config_file"])
    except:
        messenger(2, "Error reading config file: " + settings["config_file"])
        messenger(2, "Run aborted")
        return 1, settings

    if config_options.has_section("general"):
        if config_options.has_option("general", "beacon") and settings["beacon"] == 5:
            settings["beacon"] = int(config_options.get("general", "beacon"))

        if config_options.has_option("general", "additional_filters") and not settings["additional_filters"]:
            settings["additional_filters"] = config_options.get("general", "additional_filters")

    for section in config_options.sections():
        if section != "general":
            try:
                parsers.setdefault(section, []).append(re.compile(config_options.get(section, "regex")))
                parsers[section].append(config_options.get(section, "date_time"))
                parsers[section].append(config_options.get(section, "date_time_format"))
                parsers[section].append(config_options.get(section, "status"))
                parsers[section].append(config_options.get(section, "query_type"))
                parsers[section].append(config_options.get(section, "question"))
            except:
                messenger(2, "Error reading config file: " + input_file + ":" + section)
                messenger(2, "Run aborted")
                return 1, settings

    return parsers, settings

def main(argv):

    rex_windows_line = re.compile(r'(\d\d?/\d\d?/\d{4} \d\d?:\d\d:\d\d (A|P)M) .* UDP Rcv (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) .* Q \[.* ([A-Z]+)\] ([A-Z]+)\s+\(\d+\)(.*)\(0\)')
    rex_question = re.compile(r'\(\d+\)')
    rex_subdomain_defang = re.compile(r'(/)')
    no_fetch_tldextract = tldextract.TLDExtract(suffix_list_url=False)

    # Read and process command line arguements
    settings = process_command_line(argv)

    if not settings:
        return 1

    if not settings["quiet"]:
        messenger(0, "Starting " + __project__ + " v" + __version__)

    # Read and process the config file
    parsers = 0

    if settings["config_file"]:
        if not settings["quiet"]:
            messenger(0, "Reading from config file: " + settings["config_file"] )
        parsers, settings = read_config_file(settings)

    if not parsers:
        messenger(3, "No parsers defined, exiting")
        return 1

    if settings["debug"]:
        messenger(3, "Running in debug mode")
        if settings["quiet"]:
            messenger(3, "Quiet Mode overrided by debug")
            settings["quiet"] = False

    if not settings["quiet"]:
        messenger(0, "Beacon interval set to " + str(settings["beacon"]) + " (5 is the default)")
        if settings["additional_filters"]:
           messenger(0, "Additional noise filtering enabled")

    # Open input file or stdin
    if settings["input_file"]:
        if not settings["quiet"]:
            messenger(0, "Reading file: " + settings["input_file"])
        try:
            input = open(settings["input_file"], "r+")
        except:
            messenger(2, "Error reading file: " + settings["input_file"])
            messenger(2, "Run aborted")
            return 1
    else:
        if not settings["quiet"]:
            messenger(0, "Reading from stdin")
        input = sys.stdin

    # Start processing
    with input as f:

        processed = line_count = 0
        domain_count = {}

        min_timestamp = max_timestamp = 0

        for line in f:

            line_count += 1

            for parser in parsers:
                match = parsers[parser][0].search(line)

                if match:
                    date_time = match.group(int(parsers[parser][1]))
                    date_time_format = parsers[parser][2]
                    status = match.group(int(parsers[parser][3])).lower()
                    query_type = match.group(int(parsers[parser][4])).lower()

                    # Transform Windows DNS question to real FQDN
                    q_temp = rex_question.subn(".", match.group(int(parsers[parser][5])))
                    question = q_temp[0].lower().rstrip('\r')
                    break
            else:
                continue

            processed += 1

            # Only process NOERROR and NXDOMAIN statuses
            if status != "noerror" and status != "nxdomain":
                continue

            # Remove SRV and PTR query types
            if query_type == "srv" or query_type == "ptr":
                continue

            # Filter out questions less than 100 characters
            if len(question) < 100:
                continue

            # Replace illegal characters from the URL so TLDextract will work
            question = rex_subdomain_defang.sub("-", question)

            # Take apart the FQDN
            fqdn = no_fetch_tldextract(question)
            domain = fqdn.domain + "." + fqdn.suffix
            subdomain = fqdn.subdomain

            # Reduce the noise, if needed
            if settings["additional_filters"]:
                if subdomain:
                    segments = fqdn.subdomain.rsplit(".")

                    # Filter out FQDNs with less than 3 subdomain segments
                    segment_count = len(segments)
                    if segment_count < 3:
                        continue

                    # Filter out FQDNs that don't have any long sugdomain segments
                    for segment in segments:
                        if len(segment) > 50:
                            break
                    else:
                        continue

            # Hash the subdomain to store more efficiently
            subdomain_md5 = hashlib.md5(subdomain).hexdigest()

            domain_count.setdefault(domain, [])

            if subdomain_md5 not in domain_count[domain]:
                domain_count[domain].append(subdomain_md5)

            timestamp = datetime.datetime.strptime(date_time, date_time_format)

            if min_timestamp == 0 or timestamp < min_timestamp:
                    min_timestamp = timestamp
            if max_timestamp == 0 or timestamp > max_timestamp:
                    max_timestamp = timestamp

        timeframe = (max_timestamp - min_timestamp).total_seconds()

        # Calculate the threshold value from the beacon interval and the timeframe detected in the log
        threshold = timeframe / settings["beacon"]

        if settings["debug"]:
            messenger(3, "First detected timestamp: " + min_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
            messenger(3, "Last detected timstamp: " + max_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
            messenger(3, "Time Frame Processed: " + str(timeframe) + " seconds")
            messenger(3, "Threshold: " + str(threshold) + " unique subdomains")
            messenger(3, "Total Lines In Log: " + str(line_count))
            messenger(3, "Logs Passed Inital Filter: " + str(processed))

        tunnel_count = 0

        for domain in domain_count:
            if len(domain_count[domain]) > threshold:
                messenger(1, "Possible DNS Tunnel Detected: " + domain + ", " + str(len(domain_count[domain])) +
                          " unique subdomains detected")
                tunnel_count += 1
            else:
                continue

        if tunnel_count == 0 and not settings["quiet"]:
            messenger(0, "No DNS Tunnels Detected")

    if input is not sys.stdin:
        f.close()

    if not settings["quiet"]:
        messenger(0, "Finished " + __project__ + " v" + __version__)

    if tunnel_count == 0:
        return 0
    else:
        return 2

if __name__ == "__main__":
    error = main(sys.argv[1:])
    sys.exit(error)
