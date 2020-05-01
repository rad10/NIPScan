#!/usr/bin/python3
from sys import argv, exit, stdin
import socket
import re
import argparse

# make sure library is installed
try:
    import nmap
except:
    print("Error: cannot find nmap library on platform.")
    print("Please install nmap library from pip")
    print("Please run either \"pip3 install python-nmap\"")
    print("or \"sudo apt install python3-nmap\"")
    print("Exiting now")
    exit(1)

#[InitConfig]#
nm = nmap.PortScanner()  # the NMap scanning object
ip = []
opts = ["-sL"]


#[/InitConfig]#
#[Help]#
parser = argparse.ArgumentParser(
    prefix_chars="-+/", description="""this is a portscanner that takes in ip addresses
    and can do multiple things, including displaying the hostnames of each ip address,
    as well as filtering out dead ip addresses and only displaying currently alive ips.""")
display = parser.add_mutually_exclusive_group()
parser.add_argument("ips", nargs=argparse.REMAINDER, type=str,
                    metavar="ip_address", help="The IP Addresses to be scanned.")
parser.add_argument("-a", "--alive", action="store_true",
                    help="Filters only alive ips into list")
display.add_argument("-vi", "--visual", action="store_const", dest="display", default="visual", const="visual",
                     help="Gives the visual desplay of results (defualt)")
parser.add_argument("-r", dest="brute", action="store_true",
                    help="Reads ips and assumes hosts are all alive. for incase some ips block ping.")
parser.add_argument("-f", "--file", type=argparse.FileType("r"),
                    metavar="input_file", help="Imports hosts from file, fan only be used once")
parser.add_argument("-e", "--extra", nargs="+", metavar="options",
                    help="Adds extra options to nmap scanner")
parser.add_argument("-ln", "--local", action="store_true",
                    help="Adds local network addresses to scanner")
display.add_argument("-t", "--text", action="store_const", dest="display", const="text",
                     help="Changes the scripts result so that it only displays the ips given. -a and -hn will change these from defualt input")
parser.add_argument("-hn", "--hostname", action="store_true",
                    help="Addition to -t that includes hostname to raw result")

#[/Help]#
#[Config]#
if len(argv) <= 1 and stdin.isatty():
    parser.print_help()
parse = parser.parse_args()

if parse.alive:
    opts.append("-sn")
    opts.remove("-sL")
if parse.brute:
    opts.append("-Pn")

if (parse.extra != None):
    opts.extend(parse.extra)

if (parse.ips != None):
    for i in range(len(parse.ips)):
        if (re.search(r"\d{1,3}.\d{1,3}.\d{1,3}.(\d{1,3}/\d{2}|(\d{1,3}-\d{1,3}|\d{1,3}))", parse.ips[i]) == None):
            try:
                socket.gethostbyname(parse.ips[i])
            except socket.gaierror:
                parse.ips.pop(i)

    ip.extend(parse.ips)

#     elif(re.search(r"\d{1,3}.\d{1,3}.\d{1,3}.(\d{1,3}/\d{2}|(\d{1,3}-\d{1,3}|\d{1,3}))", i) != None):
#         ip.append(i)
#     else:
#         try:
#             socket.gethostbyname(i)
#         except socket.gaierror:
#             pass
#         else:
#             ip.append(i)

# [/Config]
#[STDIN]#
if not stdin.isatty():
    addin = str(stdin.read()).split()
    for term in addin:
        reg = re.search(
            r"\d{1,3}.\d{1,3}.\d{1,3}.(\d{1,3}/\d{2}|(\d{1,3}-\d{1,3}|\d{1,3}))", term)
        if (reg != None):
            ip.append(str(reg.group()))
        else:
            try:
                socket.gethostbyname(term)
            except socket.gaierror:
                pass
            else:
                ip.append(term)
#[/STDIN]#
#[LocalHosts]#
if parse.local:  # Local Network option
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
if parse.file != None:  # this will grab ip addresses from an inputed file
    doc = parse.file.read().split()
    for term in doc:
        reg = re.search(
            r"\d{1,3}.\d{1,3}.\d{1,3}.(\d{1,3}/\d{2}|(\d{1,3}-\d{1,3}|\d{1,3}))", term)
        if (reg != None):
            ip.append(str(reg.group()))
        else:
            try:
                socket.gethostbyname(term)
            except socket.gaierror:
                pass
            else:
                ip.append(term)
# [/Files]
#[Generator]#
opts.sort()

# org to filter non ip addresses
for i in range(len(ip)-1, 0, -1):
    reg = re.search(
        r"\d{1,3}.\d{1,3}.\d{1,3}.(\d{1,3}-\d{1,3}|\d{1,3})", ip[i])
    if (reg != None):
        ranges = str(reg.group()).split(".")
        for p in ranges[:2]:
            if int(p) < 0 or int(p) > 255:
                print("Pop: %s. Not a real ipv4 address" % ip[i])
                ip.pop(i)
                break
        else:
            if "-" in ranges[3]:
                ipr = ranges[3].split("-")
                if int(ipr[0]) < 0 or int(ipr[1]) > 255:
                    print("Pop: %s. Not a real ipv4 address" % ip[i])
                    ip.pop(i)
            elif int(ranges[3]) < 0 or int(ranges[3]) > 255:
                print("Pop: %s. Not a real ipv4 address" % ip[i])
                ip.pop(i)
if len(ip) == 0:
    print("Error: No valid targets given\n")
    parser.print_help()
    exit()
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
if (parse.display == "visual"):
    print("Hosts:")
    print("state | hostname (ipaddress)")
    for host in nm.all_hosts():
        if parse.alive and parse.brute:
            try:
                if (nm[host] > 0 and nm[host].hostname() != ""):
                    print(nm[host].state() + "\t| " +
                          nm[host].hostname() + " ("+host+")")
            except:
                continue
        elif parse.alive:
            # prints as [true/false] | hostname (ip address)
            print(nm[host].state() + "\t| " +
                  nm[host].hostname() + " (" + host + ")")
        else:
            if nm[host].hostname() != "":
                print(nm[host].hostname() + " (" + host + ")")
#[/Visual]#
#[Text]#
if (parse.display == "text"):
    for host in nm.all_hosts():
        if parse.hostname:  # Hostname
            if nm[host].hostname() != "":
                print(host + ":" + nm[host].hostname())
        else:
            print(host)
#[/Text]#
