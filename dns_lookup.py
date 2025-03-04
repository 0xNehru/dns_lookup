import dns.resolver
import pandas as pd
from prettytable import PrettyTable
import sys

# Subdomain Scanner tool Script by 0xNehru
# List of possible takeover patterns
TAKEOVER_PATTERNS = {
    "s3.amazonaws.com", "github.io", "herokuapp.com", "pantheon.io", "unbouncepages.com",
    "cloudfront.net", "tictail.com", "surge.sh", "bitbucket.io", "smugmug.com", "wordpress.com",
    "helpjuice.com", "helpscoutdocs.com", "amazonaws.com", "acquia-sites.com", "cargocollective.com",
    "flywheelstaging.com", "strikingly.com", "zendesk.com", "statuspage.io", "simplebooklet.com",
    "getresponse.com", "kinsta.com", "readme.io", "brightcove.com", "wufoo.com", "hatena.ne.jp",
    "activecampaign.com", "thinkific.com", "launchrock.com", "canny.io", "teamwork.com", "tilda.cc",
    "bigcartel.com", "aftership.com", "helpscout.net", "webflow.io", "ghost.io", "helprace.com"
}

# ANSI color codes
GREEN = "\033[92m"
RESET = "\033[0m"

def query_dns(subdomain, record_type):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Use Google's and Cloudflare's DNS
    try:
        answers = resolver.resolve(subdomain, record_type)
        return ', '.join([str(rdata) for rdata in answers])
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoNameservers:
        return "REFUSED"
    except (dns.resolver.NoAnswer, dns.resolver.Timeout):
        return "-"

def check_takeover(cname):
    """Check if the CNAME matches a takeover pattern"""
    if cname != "-" and cname != "NXDOMAIN":
        for pattern in TAKEOVER_PATTERNS:
            if pattern in cname:
                return True
    return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 dns_lookup_tool.py <subdomains.txt>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    try:
        with open(input_file, "r") as f:
            subdomains = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
        sys.exit(1)
    
    # Default column headers
    columns = ["Domain", "CNAME", "A", "NS", "MX", "TXT", "AAAA", "IP", "NXDOMAIN"]
    data = []
    
    for subdomain in subdomains:
        cname = query_dns(subdomain, "CNAME")
        a_record = query_dns(subdomain, "A")
        ns_record = query_dns(subdomain, "NS")
        mx_record = query_dns(subdomain, "MX")
        txt_record = query_dns(subdomain, "TXT")
        aaaa_record = query_dns(subdomain, "AAAA")
        ip_address = a_record if a_record not in ["-", "NXDOMAIN"] else "-"

        # Check NXDOMAIN status
        nx_domain_list = [a_record, ns_record, mx_record, txt_record, aaaa_record]
        if "NXDOMAIN" in nx_domain_list:
            nx_domain = "PARTIAL NXDOMAIN"
        elif cname == "NXDOMAIN" and all(record == "NXDOMAIN" for record in nx_domain_list):
            nx_domain = "NXDOMAIN"
        else:
            nx_domain = "-"

        # Mark CNAME if it matches a takeover pattern
        takeover_possible = check_takeover(cname)
        colored_cname = f"{GREEN}{cname}{RESET}" if takeover_possible else cname

        data.append([subdomain, colored_cname if cname != "NXDOMAIN" else "-", 
                     a_record if a_record != "NXDOMAIN" else "-", 
                     ns_record if ns_record != "NXDOMAIN" else "-", 
                     mx_record if mx_record != "NXDOMAIN" else "-", 
                     txt_record if txt_record != "NXDOMAIN" else "-", 
                     aaaa_record if aaaa_record != "NXDOMAIN" else "-", 
                     ip_address, nx_domain])

    # Identify columns that have useful data
    active_columns = []
    for col_idx in range(len(columns)):
        if any(row[col_idx] not in ["-", ""] for row in data):
            active_columns.append(columns[col_idx])

    # Create dynamic table based on available data
    table = PrettyTable(active_columns)
    for row in data:
        filtered_row = [row[columns.index(col)] for col in active_columns]
        table.add_row(filtered_row)

    print(table)

    # Save to Excel
    df = pd.DataFrame(data, columns=columns)
    df = df[[col for col in active_columns]]  # Keep only relevant columns
    df.to_excel("dns_lookup_results.xlsx", index=False)
    
    print("Results saved to dns_lookup_results.xlsx")

if __name__ == "__main__":
    main()
