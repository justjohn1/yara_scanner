# 🛡️ **YARA-Powered Advanced Malware Scanner** 🚀  

## **Overview**  
This **cutting-edge malware scanner** leverages the power of **YARA rules** to provide **next-generation threat detection**. Designed for **security professionals, forensic analysts, and SOC teams**, this tool goes beyond traditional YARA scanning by integrating **file intelligence, entropy analysis, VirusTotal verification, and process memory scanning**—ensuring **high-accuracy threat hunting** with **reduced false positives**.  

💡 **Detect threats hidden inside executables, documents, ISO images, binaries, and even running processes**—with full support for **any YARA signature worldwide**.  

---

## 🔥 **Key Features**  
✅ **Universal YARA Signature Compatibility** – Use **any** `.yar` ruleset from top **threat intelligence sources** like **Florian Roth, YARA-Rules, and AlienVault OTX**.  
✅ **Flexible Scanning Options** – Scan **individual files, directories, running processes, and embedded payloads**.  
✅ **Entropy-Based Malware Detection** – Identifies **obfuscated, packed, and encrypted payloads** that bypass traditional scans.  
✅ **Process Memory Scanning** – Detects malware running in **live system processes**.  
✅ **PE File Inspection** – Analyzes **executables** (`.exe, .dll, .sys, .scr, .bat, .ps1`) for **suspicious imports, entry points, and persistence mechanisms**.  
✅ **Binary & ISO Image Analysis** – Uses **Binwalk & PyCdlib** to scan **hidden files, executables, and archives inside ISOs**.  
✅ **VirusTotal API Integration** – Optionally **check flagged files** against **VirusTotal’s global malware database**.  
✅ **Risk Classification & Scoring** – Assigns **Low, Medium, or High-Risk ratings** to detected threats based on multiple factors.  
✅ **Multithreading for High-Speed Scanning** – **Optimize** performance by using **multiple threads** for parallel processing.  
✅ **Whitelisting** – Exclude **trusted files or directories** to **reduce noise and false positives**.  
✅ **Auto-Generated Reports & Alerts** – Provides **detailed forensic reports** of matched files, risk classifications, and scanning statistics.  

---

## 📦 **Installation**  
### **1️⃣ Install Dependencies**
Ensure you have `Python 3.7+` and install the required libraries:
```sh
pip install yara-python psutil pycdlib binwalk tqdm requests pefile yara
```

### **2️⃣ Clone & Set Up YARA Rules**  
Download the YARA rulesets into a single directory, each set in it's extracted folder
	You can use **any** YARA ruleset, I used:  
	- [Florian Roth’s Signature Base](https://github.com/Neo23x0/signature-base)  
	- [YARA-Rules Project](https://github.com/YARA-Rules/rules)  
	- [YARA Forge] - https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-full.zip
	- [Yaraify abuse.ch] - https://yaraify.abuse.ch/yarahub/yaraify-rules.zip
	

This code iterates through the folders specifically looking for ".yar" files. Once found, the code auto compiles them for us


### **3️⃣ Troubleshooting**
```sh
Windows
  Remove yara and re-install
Linux and MacOS
	If you have troulbe getting the code to find yara sigs try:
	    Removing yara and then fresh install::
		pip uninstall yara-python --break-system-packages
		pip uninstall yara-python --break-system-packages
		sudo apt remove yara-python
		sudo rm -rf /usr/lib/libyara.so
		sudo rm -rf /usr/lib/x86_64-linux-gnu/libyara.so
		sudo find / -name libyara.so (rm -rf all_found)
		
		
		
	    Re-install yara, then do a:
	    	echo $LD_LIBRARY_PATH
	    	[Example:]
	    	sudo ln -s /home/ecks/Downloads/software/yara/yara-4.5.1/.libs/libyara.so /usr/lib/libyara.so
	    	   The first dir is where yara is now installed ("echo $LD_LIBRARY_PATH")
	    	   	The second dir is where the code is saying it cannot find YARA...so we link it with this command.
```

## 🚀 **Usage**
### **1️⃣ Scan a Directory for Malware**
	python scanner.py --directory /path/to/folder
		Scans all files inside `/path/to/folder` using the latest YARA signatures.

### **2️⃣ Scan Running Processes for In-Memory Threats**
	python scanner.py --scan-processes
		Monitors all active processes for **malware-like behavior**.

### **3️⃣ Enable Multithreading for Faster Scanning**
	python scanner.py --directory /path/to/folder --threads 4
		Uses **4 threads** to significantly speed up scanning.

### **4️⃣ Whitelist Safe Files to Reduce False Positives**
	python scanner.py --whitelist /path/to/known_safe_file_or_folder
		Files will be hashed and **excluded** from future scans.

### **5️⃣ Enable VirusTotal Lookup for Flagged Files**
	To check flagged files against **VirusTotal**, **add your API key** in the script:
	VIRUSTOTAL_API_KEY = 'your-api-key-here'
		Then run:
		python scanner.py --directory /path/to/folder
		Any **suspicious file** will be **cross-checked** against VirusTotal's malware database.



## ⚙️ **Advanced Scanning Options**
| **Option**             | **Description** 					  | **How to Enable** |
|------------------------|----------------|-------------------|-------------------|-------------------|
| **Custom YARA Rules**  | Scan with **any** YARA rule set		 	  | Set `YARA_RULES_DIR`
| **Process Scanning**   | Scan **live system processes**		 	  | `--scan-processes'
| **Multi-Threading**    | Speed up scanning with **multiple CPU cores** 	  | `--threads X`
| **Entropy Analysis**   | Detect obfuscated malware 				  | Enabled by default
| **PE File Inspection** | Detect **suspicious Windows executables** 		  | Enabled by default 
| **ISO/Binary Analysis**| Extract hidden malware from **ISO files & binaries**   | Enabled by default 
| **Whitelist Support**  | Exclude **known-safe files** from scans 		  | `--whitelist /path/to/file`
| **VirusTotal API**     | Check flagged files against **VirusTotal** 		  | Requires API Key 

---

## 📊 **How It Works**
🔹 **Step 1: Compile & Validate YARA Rules**  
- **Automatically detects** `.yar` files in the `YARA_RULES_DIR` directory.  
- **Compiles valid rules** and **skips invalid ones**, ensuring accurate scans.  

🔹 **Step 2: Scan Files, Processes & Memory**  
- **Recursively scans files** and checks process memory for **malware artifacts**.  
- Uses **entropy analysis** to detect **packed, obfuscated, or encrypted payloads**.  
- **Identifies hidden malware** inside **ISO images, ZIP archives, and executables**.  

🔹 **Step 3: Reduce False Positives**  
- Cross-checks **flagged files** with **VirusTotal**.  
- Uses **file header analysis** to validate if file types match expectations.  
- Scores files as **Low, Medium, or High-Risk** based on **behavioral indicators**.  

🔹 **Step 4: Generate Detailed Reports**  
- Logs **all matched rules, risk levels, and flagged files**.  
- Displays **file types encountered & scanning statistics**.  
- **Interactive forensic analysis** for manual investigation.  

---

## 🏆 **Why This Scanner is Better**
✔️ **Not Just a YARA Wrapper** – Integrates **entropy analysis, risk scoring, PE file inspection, and VirusTotal API**.  
✔️ **Supports ANY YARA Rule** – Use **any** `.yar` signature from **global threat intelligence sources**.  
✔️ **Minimizes False Positives** – Uses **smart whitelisting, entropy filtering, and risk classification**.  
✔️ **Optimized for Speed & Scale** – Supports **multi-threaded scanning** for **high performance**.  
✔️ **Comprehensive Threat Hunting** – Scans **files, processes, ISOs, and binaries** for **deep analysis**.  
✔️ **Professional-Grade** – Used by **SOC analysts, malware researchers, and penetration testers**.  

---

## 🔒 **Security Disclaimer**
This script is a **malware analysis tool** intended for use by **security professionals and researchers**.  
Do **not** use it on **live production systems** unless you fully understand the risks.  

---

## 🤝 **Contributing**
Want to improve this scanner? **Pull requests are welcome!**  
- **Found a bug?** Submit an issue.  
- **Have an idea?** Suggest an enhancement.  

---

## 📜 **License**
This project is licensed under the **MIT License** – free to use, modify, and distribute.

---

### ⭐ **If this tool helped you, please give it a star on GitHub!** ⭐  
🔗 **[GitHub Repo Link](https://github.com/YOUR-GITHUB/YARA-Malware-Scanner)**  

---

🔥 **Now go hunt some malware!** 🔥  
