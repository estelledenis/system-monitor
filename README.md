The System Monitor is a security framework designed to monitor system login activities, detect unauthorized access, and enhance system security on the local system. By leveraging tools like Nmap, iptables/UFW, and python-nmap, this project provides real-time monitoring, vulnerability assessments, and automated responses to secure system resources.

## Background: System Monitoring Walkthrough ##

Below is an example of successful login attempts, including the user, login time, and IP address (if remote).

<img width="556" alt="Screen Shot 2025-01-24 at 2 20 40 PM" src="https://github.com/user-attachments/assets/824b1702-4d27-4cf3-987f-509b6c8e8090" />


Below is an example of all currently logged-in users, their terminal sessions, and login times.

<img width="322" alt="Screen Shot 2025-01-24 at 2 20 49 PM" src="https://github.com/user-attachments/assets/02dbf169-11db-44f0-85b4-1e1392ee8ecb" />


 For vulnerabilities, ports left open are a potential seccurity risk and could allow hackers to gain access to your system. The system itself has a way to heck for open ports. Below is an example of running such a command:

 
