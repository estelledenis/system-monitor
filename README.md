# Introduction #
The System Monitor provides an automated security monitoring system that helps users track login attempts, detect vulnerabilities, and manage firewall rules in a simple and user-friendly way. Designed for both technical and non-technical users, the dashboard offers real-time insights into system security by logging unauthorized access attempts, scanning for open vulnerabilities, and allowing users to customize firewall settings. And the best part is: no deep cybersecurity knowledge required!



## Background: System Monitoring ##

Today, digital security is more important than ever. Cybercriminals often try to break into personal and business computers to steal information, install malware, or take control of a system. Many users don’t realize that their systems could be vulnerable until it’s too late.

Most operating systems already have security tools built in, like system logs (which record login attempts) and firewalls (which block unauthorized access). However, these tools can be difficult to use without technical knowledge.

In an attempt to simplify the process, what follows is an explanation of these tools and how the System Monitor utilizes them.

### Login Monitoring ###

This tracks every login attempt on the system. It records details like timestamp, username, success/failure status, and IP address in order to help detect unauthorized access attempts before they become a problem.


Below is an example of successful login attempts, including the user, login time, and IP address (if remote).

<img width="556" alt="Screen Shot 2025-01-24 at 2 20 40 PM" src="https://github.com/user-attachments/assets/824b1702-4d27-4cf3-987f-509b6c8e8090" />


Below is an example of all currently logged-in users, their terminal sessions, and login times.

<img width="322" alt="Screen Shot 2025-01-24 at 2 20 49 PM" src="https://github.com/user-attachments/assets/02dbf169-11db-44f0-85b4-1e1392ee8ecb" />


### Vulnerability Scans ###


  - Vulnerability scans look for several things:
    - Open ports (entry points that attackers might exploit).
    - Services running on the system.
    - Potential security weaknesses.

For vulnerabilities, ports left open are a potential security risk and could allow hackers to gain access to your system. The system itself has a way to heck for open ports. Below is an example of running such a command:

 
![Image 2-7-25 at 6 24 PM](https://github.com/user-attachments/assets/247548c0-1977-4ac9-9e99-0de6998d6f3e)

Here, the scan results show which programs on the system are open and waiting for connections. This means different applications are running and could be accessed from outside if not properly secured.

Port 22 is open, which is for SSH. This allows remote access to the computer.

Port 631 is open, which is related to the printer system. This is usually fine unless the computer is exposed to an unsafe network.

Port 3306 is open, which means a MariaDB database is running. If this is not protected with a strong password and is accessible from outside, someone could try to access the database.

Ports 5000, 7000, and 9000 are open, showing that some web services and applications are running. One of them is Apache Tomcat, which is used for Java applications. Another is SonarQube, which is an Elasticsearch service. If these are not secured, they could be a risk.


Below is another example of a vulnerability scan:

![vulernability_scan_results](https://github.com/user-attachments/assets/6812ef12-6627-484e-a7f8-5bd291512c1f)


This is a Lynis security audit, and it has flagged several potential security issues. The scan checks various aspects of the system, including user authentication, file permissions, network settings, and software configurations. Some notable warnings include MongoDB allowing unauthorized access, lacking a firewall, weak home directory permissions, missing a malware scanner, and insecure file permissions. Additionally, it suggests installing mod_evasive and mod_security for Apache, checking symlinked mount points manually, and hardening compilers.
