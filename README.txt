Program:
-------
* This program is a Tcpdump/WireShark clone .
* It displays network packets and analyses them .


Usage :
------
usage: ./analyseur
        -i <interface> interface from where to capture packets
        -o <file> a packet file
        -f <BPF filter> filter 
        -v <1|2|3>(verbosity) verbosity to show info
        -c colorized output in terminal

Structure:
--------
* Implemented each Layer's Protocols 
=> Ethernet 
=> IP , ARP
=> TCP , UDP , ICMP , SCTP
=> FTP , TELNET , SMTP , HTTP , DNS , BOOTP DHCP , POP , IMAP 


Remarks
-------
* I tried to implement colors but since we usually debug in a external output file
and because files dont process color charcaters , the ouput won't be clear. 
* bootp.h <-> layer7_app.h

Example
-------

* To show colorized packets 
>> ./analyseur -v3 -o ./test_files/telnet_p4.pcap -c 
* To debug in a file
>> ./analyseur -v3 -o ./test_files/telnet_p4.pcap > output.debug
        
Debug Remarks
------
* The directory test_files contains multiple .pcap files
and how the program analyzed them with various verbosity 
*log1 *log2 *log3

*  Automating tests are given to simplify the task
* To remove logs
>> sh zremove_tests.sh
* To analyse all pcaps file
>> sh testauto.sh
