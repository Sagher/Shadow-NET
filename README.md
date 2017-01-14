Cross Platform Monitoring and Blocking System built in Java. The system is a light-weight background java application and is intended to be deployed on server and provide continuous monitoring of the network traffic. We are built this project for our Undergraduate Final year project. 

The core functionality of the system is to extract required information from the packets and check those credentials with provided Threat Intelligence feeds of [TRIAM](http://www.triam.com.pk) and log them into the database and provide visualization accordingly on the web interface. The feeds are updated on daily basis and contain around about 90k malicious IP sources, 10k+ URLs and the same amount of Md5 hashes of malicious files and pages. They provide categorized data according to the types of attacks i.e, Probing, Malware, Web,SIP,Ssh, Db, Md5, Url etc.

The System is also capable of blocking an ip address on linux server, this can be done from the web interface [shadownet-spring-boot](https://github.com/Sagher/shadownet-spring-boot)

***
#### Technologies Used:
  - [Jnetpcap](http://jnetpcap.com/) library to sniff the packets. 
  - [Mongodb](https://www.mongodb.com/download-center?jmp=nav#community) for storing packets for visualization and analysis purposes. 
  - [Log4j](http://logging.apache.org/log4j/2.x/) for logging all the activities of the application.



#### To execute on linux environment you would need:
- Latest [Jnetpcap](http://jnetpcap.com/). 
- [Mongodb](https://www.mongodb.com/download-center?jmp=nav#community) server installed
- You would have to place the libjnetpcap.so file in usr/lib directory. 
- Once the project is imported as an Existing 'Maven Project' in an IDE, add External .jar files found in the Shadow-NET/lib directory. 
- The rest of the dependencies are downloaded from Maven repositories which are mentioned in /pom.xml.


___

#### Three Types of Documents are inserted in Mongodb, which are:

##### 1. TCP Packets: 

![ScreenShot](https://cloud.githubusercontent.com/assets/20042101/19209636/26f54f2e-8d28-11e6-827a-b8d2e92a2114.jpg)

##### 2. Http Request Packets

![ScreenShot](https://cloud.githubusercontent.com/assets/20042101/19209637/26f769d0-8d28-11e6-853a-59dfe25b252f.jpg)

##### 3. Reassembled Http Contents Md5 Hashed packets:

![ScreenShot](https://cloud.githubusercontent.com/assets/20042101/19209638/26f90b32-8d28-11e6-9fbb-7b2fc8907c49.jpg)


___

#### We have been able to reassemble HttpContent from the tcp segments, following screenshots show the side by side comparison of http reassembley from Shadow-NET and Wireshark:

##### 1. Request for the same URL captured:

![ScreenShot](https://cloud.githubusercontent.com/assets/20042101/19209641/2c28b378-8d28-11e6-9f22-1c87027cfedb.jpg)


##### 2. Same number of segments(i.e. 59) reassembled to see the whole http content:

![ScreenShot](https://cloud.githubusercontent.com/assets/20042101/19209642/3148a462-8d28-11e6-86c1-039358cbb2e2.jpg)


##### 3. Same response header, same content length(i.e. 82093)

![ScreenShot](https://cloud.githubusercontent.com/assets/20042101/19209643/36544f4c-8d28-11e6-8069-cdddcb6303ac.jpg)



---
---
### We have also created and a Web based DashBoard using:
- Spring MVC
- Thymeleaf
- Jquery
- Bootstrap

Check it out at: [shadownet-spring-boot](https://github.com/Sagher/shadownet-spring-boot)


