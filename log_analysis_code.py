import re
from collections import Counter , defaultdict
import csv
file_name= r"c:\Users\rdeva\OneDrive\Documents\sample.log" 
FAILED_LOGIN_THRESHOLD=10

def parse_log_file(file_name):
    """read the log file and extract relevant data."""
    ip_pattern= re.compile(r'^(\d+\.\d+\.\d+\.\d+)')
    endpoint_pattern=re.compile(r'\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)(.*?)HTTP')
    failed_login_pattern=re.compile(r'401.*"Invalid credentials')

    ip_counts =Counter()
    endpoint_counts=Counter()
    failed_logins=defaultdict(int)
    
    try:
        with open(file_name,'r') as log_file:
            
            for line in log_file:
                ip_match = ip_pattern.match(line)
                
                if ip_match:
                    ip = ip_match.group(1)
                    ip_counts[ip]+=1
                    endpoint_match = endpoint_pattern.search(line)
                    
                    if endpoint_match:
                        endpoint= endpoint_match.group(1)
                        endpoint_counts[endpoint]+=1
                        
                        if '401' in line and 'invaild credentials' in line:
                            
                            if ip_match:
                                failed_logins[ip]+=1
    
    except FileNotFoundError: 
        print(f"Error : File not found at {file_name}")
        return None, None, None
    return ip_counts,endpoint_counts,failed_logins 

def save_results_to_csv(ip_counts,most_accessed_endpoints,failed_logins,output_file):
    """saves the results to a csv file."""
    with open(output_file,'w',newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["requests per IP"])
        writer.writerow(["IP Address","Request Count"])
        
        for ip,count in ip_counts.items():
            writer.writerow([ip,count])
        writer.writerow([])
        writer.writerow(["most accessed endpoint"])
        writer.writerow(["endpoint","access count"])
        writer.writerow(most_accessed_endpoints)

        writer.writerow([])
        writer.writerow(["suspicious activity detected"])
        writer.writerow(["IP Address","Failed Login Count"])
        
        for ip,count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip,count])

def main():
    ip_counts,endpoints_counts,failed_logins= parse_log_file(file_name)
    
    if ip_counts is None:
        return
    print(f"{'IP Address':<20} {'Request count':<15}")
    print("_"*35)
    
    for ip,count in sorted(ip_counts.items(),key=lambda x:x[1],reverse =True):
        print(f"{ip:<20}{count:<15}")
        most_accessed_endpoint= max(endpoints_counts.items(),key=lambda x:x[1])
        print("\nMost frequentlu accessed endpoint:")
        print(f"{most_accessed_endpoint[0]}(accessed{most_accessed_endpoint[1]}times)")
        print("\n non suspicious activity detected:")
        print(f"{'IP Address':<20} {'failed login attempt':<15}")
        print("-"*35)
        
        for ip,count in failed_logins.items():
            
            if count> FAILED_LOGIN_THRESHOLD:
                print(f"{ip:<20} {count:<15}")
        output_file="logs_analysis_results.csv"
        save_results_to_csv(ip_counts,most_accessed_endpoint,failed_logins,output_file)
        print(f"\nresults saved to{output_file}")

if __name__ == "__main__":
    main()


