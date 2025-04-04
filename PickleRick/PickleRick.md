# 🥒 Pickle Rick Challenge  
**Difficulty:** Easy  

## 📝 Challenge Overview  
In this challenge, we have to exploit a web server and find **three ingredients** to help Rick make his potion and transform himself back into a human from a pickle.  

---

## 🔍 Step 1: Port Scanning  

We start by scanning the target machine for open ports using `nmap`:  

```bash
sudo nmap <IP_ADDR> -T4
```
![Nmap Scan Results](images/Nmapscan.png)

✅ Findings:

Port 22 (SSH) – Might be useful later.
Port 80 (HTTP) – Let's check the website.

## 🔎 Step 2: Directory Enumeration
Since the website doesn’t reveal much, we use Gobuster to enumerate directories.

```bash
gobuster dir -u http://<IP_ADDR> -x php,txt,json,js,css,pdf -w /usr/share/wordlists/dirb/common.txt
```
![Gobuster Scan Results](images/gobusterscan.png)

✅ Findings:

/robots.txt
/index.html
/login.php
