# DNS Lookup & Subdomain Takeover Scanner
# dns_lookup.py
This Python script performs DNS enumeration on a list of subdomains and checks for potential subdomain takeovers. It queries various DNS records (A, CNAME, MX, NS, TXT, AAAA) and highlights possible takeover vulnerabilities based on known patterns. The results are displayed in a structured table and saved as an Excel file for further analysis.

# Features

✅ Queries A, CNAME, MX, NS, TXT, AAAA records
✅ Identifies NXDOMAIN and partial DNS failures
✅ Detects potential subdomain takeovers
✅ Exports results to Excel (dns_lookup_results.xlsx)
✅ Uses Google (8.8.8.8) & Cloudflare (1.1.1.1) DNS resolvers
# Usage

python3 dns_lookup_tool.py subdomains.txt

# 📌 Ensure you have the required modules installed:

pip install dnspython pandas prettytable openpyxl

# Author

# 👨‍💻 0xNehru

