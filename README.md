#Quick start:<br/>
The cli support command:<br/>
start<br/> 
    - (packets are being sniffed from now on from default iface(eth0))<br/>
stop <br/>
    - (packets are not sniffed)<br/>
show [ip] count <br/>
    -(print number of packets received from ip address)<br/>
select iface [iface] <br/>
    -(select interface for sniffing eth0, wlan0, ethN, wlanN...)<br/>
stat [iface] <br/>
    - show all collected statistics for particular interface, if iface omitted - for all interfaces.<br/>
 --help <br/>
  -(show usage information)<br/>
The program running in the background. After sniff start you must use sniff stop to stop the daemon.<br/>
The program uses a libpcap library for catching packages.
