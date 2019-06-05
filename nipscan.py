#!/usr/bin/python
import nmap
from sys import argv, exit
import socket

#[InitConfig]#
nm = nmap.PortScanner()
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
#a = argv[1:]
if len(argv) <= 1:
    help()
for i in argv[1:]:
    if narg=="e":
        opts.append(i)
        narg=""
        continue
    elif narg=="f":
        fle = str(i)
        narg=""
        continue
    i = i.lower()
    if (i=="-a" or i=="-alive" or i=="--alive"):
        opts.append("-F")
        opts.remove("-sL")
        alive = True
    elif (i=="-vi" or i=="-visual" or i=="--visual"):
        visual = True
        text = False
    elif (i=="-t" or i=="-text" or i=="--text"):
        text = True
        visual = False
    elif (i=="-r"):
        opts.append("-Pn")
        brute = True
    elif (i=="-ar" or i=="-ra"):
        opts.append("-F")
        opts.append("-Pn")
        opts.remove("-sL")
        brute = alive = True
    elif (i=="-f" or i=="-file" or i=="--file"):
        narg = "f"
        bfle = True
    elif (i=="-e" or i=="-extra" or i=="--extra"):
        narg = "e"
    elif (i=="-ln" or i=="-local" or i=="--local"): ln = True
    elif (i=="-hn" or i=="-hostname" or i=="--hostname"): hn = True
    elif (i=="-thn" or i=="-hnt"):
        hn = text = True
        visual = False
    elif (i=="-h" or i=="-help" or i=="--help"): help()
    elif (i[0]=="-"):
        print("Error: "+i+" command not found\n")
        help()
    else:
        ip.append(i)
#[/Config]
#[LocalHosts]#
if ln:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    localip = s.getsockname()[0]
    s.close()
    sets = localip.split(".")
    ip.append(str(sets[0]+"."+sets[1]+"."+sets[2]+".0-255"))
#[/LocalHosts]#
#[Files]#
if bfle:
    doc = str(open(fle, "r").read())
    if len(doc.split("\n"))>1:
        for lines in doc.split("\n"): ip.append(lines)
    elif len(doc.split("\t"))>1:
        for tabs in doc.split("\t"): ip.append(tabs)
    elif len(doc.split(", "))>1:
        for commaSpace in doc.split(", "): ip.append(commaSpace)
    elif len(doc.split(","))>1:
        for comma in doc.split(","): ip.append(comma)
    elif len(doc.split(" "))>1:
        for space in doc.split(" "): ip.append(space)
    else: ip.append(doc)
#[/Files]
#[Generator]#
opts.sort()
count = 0
while count < len(opts)-1:
    if opts[count] == opts[count+1]:
        opts.pop(count)
    else: count += 1

sopts = opts[0]
sips = ip[0]
for i in opts[1:]: sopts += (" "+i)
for i in ip[1:]: sips += (" "+i)
#print(sopts)
#print(sips)
nm.scan(arguments=sopts, hosts=sips)
#print(nm.all_hosts())
#print(nm.command_line())
#[/Generator]#
#[Visual]#
if visual:
    print("Hosts:")
    print("state | hostname (ipaddress)")
    for host in nm.all_hosts():
        if alive and brute:
            try:
                if (nm[host] > 0 and nm[host].hostname() != ""): print(nm[host].state()+"\t| "+nm[host].hostname()+" ("+host+")")
            except:
                continue
        elif alive: print(nm[host].state()+"\t| "+nm[host].hostname()+" ("+host+")")
        else:
            if nm[host].hostname() != "":
                print(nm[host].hostname()+" ("+host+")")
#[/Visual]#
#[Text]#
if text:
    for host in nm.all_hosts():
        if hn:
            if nm[host].hostname() != "": print(host+":"+nm[host].hostname())
        else: print(host)
#[/Text]#