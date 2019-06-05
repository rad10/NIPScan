# NIPScan
Nmap IP Scan tool. used for finding machines on a local network as well as their machine name.

Nmap Ip Scan is a program that takes a list of ip addresses or group of ip addresses and gives a list of alive hosts along with possible hostnames

!!Requires nmap to run!!

### Help and Options

> ``nipscan.py [OPTIONS] [IPADDRESSES]``

>> nipscan.py is a that takes in ip addresses and can do multiple things, including displaying the hostnames of each ip address, as well as filtering out dead ip addresses and only displaying currently alive ips.

>> OPTIONS:

>>> ``-a | (-)-alive`` Filters results to only currently active machines.

>>> ``-f | (-)-file`` Input ip list from file.

>>> ``-tl | (-)-textlist [default]`` Input ip's. it can be 1 or more, but to have you multiple it must be in quotes and there has to be a space in between each ip address. you can also scan multiple addresses with a - in between the numbers
Example: "123.456.789.101 987.654.321.012" "123.832.1.0-255 101.204.294.103"

>>> ``-ln | (-)-local`` Scans entire local network. no given ip address is required

>>> ``-vi | (-)-visual [default]`` Gives you a visual with alive machine ip's and names. it is on by default

>>> ``-t`` simple output. doesnt give names, but gives alive ips in list to be used by other programs

>>> ``-e | (-)-extra`` Add extra Args for scan (Specifically nmap options)