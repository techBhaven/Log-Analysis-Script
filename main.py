#importing libraries in python 1.re library to understand log pattern 2.csv to write files in csv
import re
import csv

#Giving format to sort the line in their specific  terms
LOG_PATTERN = r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[(?P<timestamp>[^\]]+)\] "(?P<method>[A-Z]+) (?P<endpoint>/[\w./-]*) HTTP/[\d.]+" (?P<status>\d{3}) (?P<size>\d+)(?: "(?P<error_message>[^"]+)")?'

#Created all 3 output Dictionary
ip_count= {}
endpoint_count={}
flagged_ip_count = {}

def parse_log_lines(lines):#function for matching log file line and grouping them
    for line in lines:
        match = re.match(LOG_PATTERN, line)
        if match:
            yield match.groupdict()

def print_ipcount_table():
    print("IP Address       Request count")
    for key, value in ip_count.items():
        print(f"{key}       {value}")
    print()

def print_mostAccessed_Endpoint():
    print("Most Frequently Accessed Endpoint:")
    most_accessed_endpoint = max(endpoint_count, key=endpoint_count.get)
    print(f"{most_accessed_endpoint} (Accessed {endpoint_count[most_accessed_endpoint]} times.)")
    print()

def print_suspicious_activity():
    print("Suspicious Activity Detected:")
    print("IP Address       Failed Login Attempts")
    for key, value in flagged_ip_count.items():
        print(f"{key}       {value}")

#appending value in list from log file
log_lines = []
with open('sample.log', 'r') as file:
    for line in file:
        a=line.strip()
        log_lines.append(a)

#Appending values of counted task to specific dictionay
for entry in parse_log_lines(log_lines):
    ip_count[entry['ip']] = ip_count.get(entry['ip'],0) +1 #counting no of occurence in ip
    endpoint_count[entry['endpoint']] = endpoint_count.get(entry['endpoint'],0) +1  #counting no of occurence of endpoint
    if(entry['status']=='401' or entry['error_message']=='Invalid credentials'): #counting no of occurence in Flagged ip
        flagged_ip_count[entry['ip']] = flagged_ip_count.get(entry['ip'],0) +1

#printing output in Terminal
print_ipcount_table()
print_mostAccessed_Endpoint()
print_suspicious_activity()

# Write to CSV
file_name = "log_analysis_results.csv"
with open(file_name, mode='w', newline='') as file:
    w = csv.writer(file)
    
    w.writerow(["Requests per IP"])
    w.writerow(["IP Address", "Request Count"])
    for ip, count in ip_count.items():
        w.writerow([ip, count])
    
    w.writerow([])

    w.writerow(["Most Accessed Endpoint"])
    w.writerow(["Endpoint", "Access Count"])
    for endpoint, count in endpoint_count.items():
        w.writerow([endpoint, count])
    
    w.writerow([])
    w.writerow(["Suspicious Activity"])
    w.writerow(["IP Address", "Failed Login Count"])
    for ip, count in flagged_ip_count.items():
        w.writerow([ip, count])
