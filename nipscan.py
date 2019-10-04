#!/usr/bin/python
import nmap
from sys import argv, exit
import socket
import re

#[InitConfig]#
nm = nmap.PortScanner()  # the NMap scanning object
ip = []
opts = ["-sL"]
visual = True
text = bfle = ln = alive = hn = brute = False
narg = ""
fle = ""

#[/InitConfig]#
#[Help]#


def help():
    print("nipscan.py [OPTIONS] [IPADDRESSES]")
    print("nipscan.py is a that takes in ip addresses and can do multiple things, including displaying the hostnames of each ip address, as well as filtering out dead ip addresses and only displaying currently alive ips.")
    print("\nOPTIONS:\n")
    print("-a/(-)-alive\t\tFilters only alive ips into list")
    print("-vi/(-)-visual\t\tGives the visual desplay of results (defualt)")
    print("-r\t\t\tReads ips and assumes hosts are all alive. for incase some ips block ping.")
    print("-f/(-)-file\t\tImports hosts from file, fan only be used once")
    print("-e/(-)-extra\t\tAdds extra options to nmap scanner")
    print("-ln/(-)-local\t\tAdds local network addresses to scanner")
    print("-t/(-)-text\t\tChanges the scripts result so that it only displays the ips given. -a and -hn will change these from defualt input")
    print("-hn/(-)-hostname\tAddition to -t that includes hostname to raw result")
    exit()


#[/Help]#
#[Config]#
if len(argv) <= 1:
    help()
for i in argv[1:]:
    if narg == "e":
        opts.append(i)
        narg = ""
        continue
    elif narg == "f":
        fle = str(i)
        narg = ""
        continue
    i = i.lower()
    if (i == "-a" or i == "-alive" or i == "--alive"):
        opts.append("-F")
        opts.remove("-sL")
        alive = True
    elif (i == "-vi" or i == "-visual" or i == "--visual"):
        visual = True
        text = False
    elif (i == "-t" or i == "-text" or i == "--text"):
        text = True
        visual = False
    elif (i == "-r"):
        opts.append("-Pn")
        brute = True
    elif (i == "-ar" or i == "-ra"):
        opts.append("-F")
        opts.append("-Pn")
        opts.remove("-sL")
        brute = alive = True
    elif (i == "-f" or i == "-file" or i == "--file"):
        narg = "f"
        bfle = True
    elif (i == "-e" or i == "-extra" or i == "--extra"):
        narg = "e"
    elif (i == "-ln" or i == "-local" or i == "--local"):
        ln = True
    elif (i == "-hn" or i == "-hostname" or i == "--hostname"):
        hn = True
    elif (i == "-thn" or i == "-hnt"):
        hn = text = True
        visual = False
    elif (i == "-h" or i == "-help" or i == "--help"):
        help()
    elif (i[0] == "-"):
        print("Error: " + i + " command not found\n")
        help()
    elif(re.search(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}", i) != None):
        ip.append(i)
# [/Config]
#[LocalHosts]#
if ln:  # Local Network option
    # opens a socket on computer to connect to internet
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # Talks to dns provider from google
    localip = s.getsockname()[0]  # this will get the local ip
    s.close()  # Turns off socket for possible later use
    sets = localip.split(".")  # splits 4 sections for use in next line
    ip.append(str(sets[0] + "." + sets[1] + "." +
                  sets[2] + ".0-255"))  # 192.168.1.0-255
#[/LocalHosts]#
#[Files]#
if bfle:  # this will grab ip addresses from an inputed file
    doc = str(open(fle, "r").read())
    matches = re.finditer(
        r"\d{1,3}.\d{1,3}.\d{1,3}.(\d{1,3}-\d{1,3}|\d{1,3})", doc, re.MULTILINE)
    for null, match in enumerate(matches, start=1):
        # itll find all relevant ip addresses and add them accordingly
        ip.append(str(match.group()))
# [/Files]
#[Generator]#
opts.sort()

# org to filter non ip addresses
for i in range(len(ip)-1, 0, -1):
    ranges = ip[i].split(".")
    for p in ranges[:2]:
        if int(p) < 0 or int(p) > 255:
            ip.pop(i)
            break
    else:
        if "-" in ranges[3]:
            ipr = ranges[3].split("-")
            if int(ipr[0]) < 0 or int(ipr[1]) > 255:
                ip.pop(i)
        elif int(ranges[3]) < 0 or int(ranges[3]) > 255:
            ip.pop(i)
count = 0
while count < len(opts) - 1:  # This whole section if to remove duplicate options
    if opts[count] == opts[count + 1]:
        opts.pop(count)
    else:
        count += 1

sopts = opts[0]
sips = ip[0]
for i in opts[1:]:
    sopts += (" " + i)  # organizes all string options with a space separation
for i in ip[1:]:
    sips += (" " + i)  # organizes all ip addresses with a space as separation

nm.scan(arguments=sopts, hosts=sips)
#[/Generator]#
#[Visual]#
if visual:
    print("Hosts:")
    print("state | hostname (ipaddress)")
    for host in nm.all_hosts():
        if alive and brute:
            try:
                if (nm[host] > 0 and nm[host].hostname() != ""):
                    print(nm[host].state() + "\t| " +
                          nm[host].hostname() + " ("+host+")")
            except:
                continue
        elif alive:
            # prints as [true/false] | hostname (ip address)
            print(nm[host].state() + "\t| " +
                  nm[host].hostname() + " (" + host + ")")
        else:
            if nm[host].hostname() != "":
                print(nm[host].hostname() + " (" + host + ")")
#[/Visual]#
#[Text]#
if text:
    for host in nm.all_hosts():
        if hn:  # Hostname
            if nm[host].hostname() != "":
                print(host + ":" + nm[host].hostname())
        else:
            print(host)
#[/Text]#
