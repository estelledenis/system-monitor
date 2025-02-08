The System Monitor is a security framework designed to monitor system login activities, detect unauthorized access, and enhance system security on the local system. By leveraging tools like Nmap, iptables/UFW, and python-nmap, this project provides real-time monitoring, vulnerability assessments, and automated responses to secure system resources.

## Background: System Monitoring ##

Below is an example of successful login attempts, including the user, login time, and IP address (if remote).

<img width="556" alt="Screen Shot 2025-01-24 at 2 20 40 PM" src="https://github.com/user-attachments/assets/824b1702-4d27-4cf3-987f-509b6c8e8090" />


Below is an example of all currently logged-in users, their terminal sessions, and login times.

<img width="322" alt="Screen Shot 2025-01-24 at 2 20 49 PM" src="https://github.com/user-attachments/assets/02dbf169-11db-44f0-85b4-1e1392ee8ecb" />


 For vulnerabilities, ports left open are a potential security risk and could allow hackers to gain access to your system. The system itself has a way to heck for open ports. Below is an example of running such a command:

 
![Image 2-7-25 at 6 24 PM](https://github.com/user-attachments/assets/247548c0-1977-4ac9-9e99-0de6998d6f3e)

Here, the scan results show which programs on the system are open and waiting for connections. This means different applications are running and could be accessed from outside if not properly secured.

Port 22 is open, which is for SSH. This allows remote access to the computer.

Port 631 is open, which is related to the printer system. This is usually fine unless the computer is exposed to an unsafe network.

Port 3306 is open, which means a MariaDB database is running. If this is not protected with a strong password and is accessible from outside, someone could try to access the database.

Ports 5000, 7000, and 9000 are open, showing that some web services and applications are running. One of them is Apache Tomcat, which is used for Java applications. Another is SonarQube, which is an Elasticsearch service. If these are not secured, they could be a risk.
