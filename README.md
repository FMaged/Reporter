# Linux Reporter (Metasploit Post Module)

## Overview  
**Linux Reporter** is a custom Metasploit **post-exploitation module** written in Ruby.  
Its purpose is to **collect and organize important Linux system information** into a structured local report.  

I built this project to **learn how Metasploit modules work, explore important Linux files, and practice Ruby programming**.  
It is not intended for malicious use — only for **education, research, and authorized testing**.  

---

## Features  
The module retrieves system information from predefined categories and optionally from **custom paths**.  
Collected data can be saved locally in a structured report folder or printed directly to the console.  

**Categories:**  
- **OS** – Distribution and kernel details  
- **Hardware** – CPU, memory, vendor information  
- **Network** – Hostname, routing, ARP table, DNS configuration  
- **User** – Accounts, groups, sudoers, bash history  
- **Configuration** – System and service config files (sysctl, fstab, SSH, cron, web servers, databases)  
- **Logs** – System and service logs (auth, syslog, dmesg, Apache, Nginx, MySQL, PostgreSQL)  
- **Custom** – Any additional paths provided by the user  

---

## Usage  
Examples of how to run the module inside Metasploit:

1. **Save all categories to the default location**:
   ```bash
   set PRINT_CONTENT false
   run

2. **Save only OS and User categories to a custom directory**:
   ```bash
   set OUTPUT_DIR /home/<your_user>/Desktop
   set CATEGORIES Os,User
   set PRINT_CONTENT false
   run

3. **Print the contents without saving**:
   ```bash
   set CATEGORIES Os,Network
   set PRINT_CONTENT true
   run

4. **Load custom paths from a file**
   ```bash
   set PATHS_FILE /home/<your_user>/custom_paths.txt
   set CATEGORIES custom
   run

## Learning Goals

This project helped me learn:

- How **Metasploit post modules** are structured (options, datastore, categories)  
- Important **Linux system files** and where critical information is stored  
- Writing and organizing code in **Ruby**  
- Basics of **post-exploitation reporting** workflows


## Disclaimer ⚠️

This module is for **educational purposes only**.  
Running it on systems you do not own or have explicit permission to test is **illegal** and against Metasploit’s intended use.  
Use it only in **controlled environments**, such as labs or authorized penetration tests.

