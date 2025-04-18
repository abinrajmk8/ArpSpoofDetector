# ARP Spoofing Detection and Attack Simulation Toolkit

This project provides a set of Python tools for simulating and detecting ARP spoofing attacks. It includes a packet sniffer, an ARP spoofing detector, an ARP spoof attack simulator, and a utility to dynamically detect the active network interface. This project is intended for educational purposes and should be used in controlled environments only.

---

Table of Contents:

1. Overview of Each Script  
2. Python Installation  
3. Setting Up the Virtual Environment  
4. Installing Required Modules  
5. Running the Project (Step-by-Step)  
6. Contact  
7. License

---

1. Overview of Each Script

- arp_spoofing_detector.py  
  Detects ARP spoofing attacks in real-time. It uses packet sniffing and MAC address validation to alert if a spoofed ARP packet is detected. This is the main detection script.

- attack_simulator.py  
  Simulates an ARP spoofing attack by sending forged ARP replies to a victim and the gateway. Can be used to test the detector in a local environment. Must be stopped with CTRL + C, which will restore the ARP tables to prevent disruption.

- packet_sniffer.py  
  Sniffs HTTP traffic and attempts to detect potential login information like usernames and passwords in plaintext HTTP requests. Useful for understanding how sensitive information can be captured over insecure protocols.

- interface_fetcher.py  
  Fetches the active network interface used by your system. This is used by the other scripts to determine which interface to sniff traffic on, so you don’t have to specify it manually. This is especially used by the ARP spoofing detector.

---

2. Python Installation

Ensure you have Python 3.8 or later installed.

For Windows:

1. Download Python from https://www.python.org/downloads/
2. Run the installer.
3. During installation, check the box that says "Add Python to PATH".
4. After installation, confirm with:

   python --version

For Linux/macOS:

Most systems come with Python pre-installed. To verify:

   python3 --version

If not installed:

Ubuntu/Debian:

   sudo apt update  
   sudo apt install python3 python3-pip

Fedora:

   sudo dnf install python3

macOS (Homebrew):

   brew install python

---

3. Setting Up the Virtual Environment

Creating a virtual environment keeps your dependencies isolated.

For Windows:

   python -m venv venv  
   venv\Scripts\activate

For Linux/macOS:

   python3 -m venv venv  
   source venv/bin/activate

---

4. Installing Required Modules

This project depends on the Scapy library.

To install it:

   pip install scapy

Or using a requirements.txt file:

   echo scapy > requirements.txt  
   pip install -r requirements.txt

---

5. Running the Project (Step-by-Step)

Step 1: Start ARP Spoofing Detection

This is the main script. Run this first.

   python arp_spoofing_detector.py

- Automatically detects your active network interface  
- Monitors ARP traffic  
- Detects and warns about spoofing attempts

Step 2: Simulate ARP Spoofing Attack (Optional)

Use this to test the detector.

1. Edit target and gateway IPs inside attack_simulator.py  
2. Run:

   python attack_simulator.py

3. Stop with CTRL + C. The script will restore the original ARP tables.

Warning: Only run in isolated lab environments.

Step 3: Run Packet Sniffer (Optional)

   python packet_sniffer.py

- Sniffs HTTP requests  
- Shows visited URLs and possible login info  
- Note: Works only for HTTP (not HTTPS)

---

6. Contact

For any questions or collaboration, feel free to reach out:

Name: Abin Raj  
Email: abinrajmk8@gmail.com

---

7. License

This project is licensed under a modified MIT License for personal and educational use only. See the [LICENSE.md](LICENSE.md) file for details.

---

Note: This toolkit is intended for ethical testing and educational use only. Do not use it on unauthorized or public networks.
