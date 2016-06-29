Cross Platform Intrusion Detection and Prevention System built in Java. The system would be a light-weight background java application and is intended to be deployed on server and provide continuous monitoring of the network traffic. 

We are building this project for our Undergraduate Final year project. 
The project is currently in its early stages and is expected to be complete around October.

We are using Jnetpcap(http://jnetpcap.com/) library to sniff the packets. 

The core functionality of the system is to extract required information from the packets and check those credentials with provided Threat Intelligence feeds of http://www.triam.com.pk/ and log them into the database and provide visualization accordingly on the web interface.
The feeds are updated on daily basis and contain around about 50k malicious IP sources and 10k+ URLs. They provide categorized data according to the types of attacks i.e, Web, Db, Md5, Url etc.

SO far we have been able to extract the packets info and check its source against the malicious IPs feeds and extract http URLs and check them against the URLs feed.
