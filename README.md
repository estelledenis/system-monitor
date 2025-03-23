# Introduction #
The System Monitor provides an automated security monitoring system that helps users track login attempts, detect vulnerabilities, and manage firewall rules in a simple and user-friendly way. Designed for both technical and non-technical users, the dashboard offers real-time insights into system security by logging unauthorized access attempts, scanning for open vulnerabilities, and allowing users to customize firewall settings. And the best part is: no deep cybersecurity knowledge required!



## Background: System Monitoring ##

Today, digital security is more important than ever. Cybercriminals often try to break into personal and business computers to steal information, install malware, or take control of a system. Many users don’t realize that their systems could be vulnerable until it’s too late.

Most operating systems already have security tools built in, like system logs (which record login attempts) and firewalls (which block unauthorized access). However, these tools can be difficult to use without technical knowledge.

In an attempt to simplify the process, what follows is an explanation of these tools and how the System Monitor utilizes them.

### Login Monitoring ###

### 🔹 What is Login Monitoring?
**Login monitoring** tracks every login attempt on a system to detect unauthorized access and security threats.

### 🔹 What Does It Record?
- **📅 Timestamp** – Logs the exact date and time of each login attempt.
- **👤 Username** – Identifies which account was used for the login attempt.
- **✅ Success/❌ Failure Status** – Indicates whether the login was successful or failed.
- **🌍 IP Address** – Captures the source of the login attempt.


Below is an example of the log monitoring output on the System Monitor application.

![0E45BC98-019F-4CCE-99E6-CCFDF883E102](https://github.com/user-attachments/assets/158a278a-b87e-4204-a581-ec1369262c79)

![556B0190-6E79-4A50-9CD8-25419C4D7444](https://github.com/user-attachments/assets/f3f0ff58-c3d0-46e5-92c5-dccf88e6928b)


### Vulnerability Scans ###

### 🔹 What Are Vulnerability Scans?
A **vulnerability scan** is an automated process that identifies security weaknesses in a system, network, or application. It helps organizations detect and mitigate potential threats before they can be exploited.

### 🔹 What Do Vulnerability Scans Look For?
- **🛠️ Open Ports** – Identifies entry points that attackers might exploit.
- **⚙️ Running Services** – Detects active services that could be potential targets.
- **🔓 Security Weaknesses** – Finds misconfigurations, outdated software, and vulnerabilities.

For vulnerabilities, ports left open are a potential security risk and could allow hackers to gain access to your system. The system itself has a way to check for open ports. Below is an example of running such a command:

 
![Image 2-7-25 at 6 24 PM](https://github.com/user-attachments/assets/247548c0-1977-4ac9-9e99-0de6998d6f3e)

Here, the scan results show which programs on the system are open and waiting for connections. This means different applications are running and could be accessed from outside if not properly secured.

Port 22 is open, which is for SSH. This allows remote access to the computer.

Port 631 is open, which is related to the printer system. This is usually fine unless the computer is exposed to an unsafe network.

Port 3306 is open, which means a MariaDB database is running. If this is not protected with a strong password and is accessible from outside, someone could try to access the database.

Ports 5000, 7000, and 9000 are open, showing that some web services and applications are running. One of them is Apache Tomcat, which is used for Java applications. Another is SonarQube, which is an Elasticsearch service. If these are not secured, they could be a risk.


Below is an example of a vulnerability scan output on the System Monitor application:


![93FBE3CE-017A-4DA5-985A-3D3AA6CF622B](https://github.com/user-attachments/assets/f73bf648-f2f3-4700-93b8-b7bedf34f465)



### Firewall Configuration ###

### 🔹 What is a Firewall?
A **firewall** is a security system that monitors and controls incoming and outgoing network traffic based on predefined rules. It acts as a barrier between a trusted internal network and external threats.

### 🔹 Why Are Firewalls Important?
- **🚫 Prevents Unauthorized Access** – Blocks malicious or unauthorized connections.
- **🛡️ Protects Against Cyber Threats** – Shields systems from malware, viruses, and hacking attempts.
- **🔍 Regulates Network Traffic** – Filters and controls data flow based on security policies.
- **🔒 Enhances Privacy & Data Security** – Prevents data breaches by blocking unauthorized transfers.
- **📊 Monitors & Logs Activity** – Keeps records of network activity for threat detection and analysis.


Below is an example of the result of the firewall rule creation on the System Monitor application.

![FE89B0C1-DF82-4B8D-A65E-5A5214A18375](https://github.com/user-attachments/assets/466a521f-9b20-4289-a852-d2c4d659eb43)




## 🚀 Installation & Usage ##

### Requirements ###
- Python 3.9 or newer
- Nmap installed
- macOS 11 or higher


### 1. Clone the repository ###
```git clone https://github.com/estelledenis/system-monitor.git```

```cd system-monitor```


### 2. Set up virtual environment ###
```python3 -m venv venv```

```source venv/bin/activate```

```pip install -r requirements.txt```


### 3. Run the app ###
```bash start_dashboard.sh```

### 4. Apply firewall rules (after vulnerability scan) ###
After running a vulnerability scan and firewall generation, activate the rules manually by clicking the "Copy Firewall Command" button. Open a new terminal and run the command.
