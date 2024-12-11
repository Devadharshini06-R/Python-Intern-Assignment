# Python

## Code Requirements

1. Count request per **IP Address**

The number of requests made by each IP address.

It is displayed in a with two columns: the IP address and the corresponding count for each request.

 ```python
   requests per IP	
IP Address	Request Count
192.168.1.1	7
203.0.113.5	8
10.0.0.2	6
198.51.100.23	8
192.168.1.100	5
```
2.Identify the most Frequently Accessed Endpoint

The script extracts endpoints form the log file , identifies the most accessed endpoint is `/login`

```python
Most Frequently Accessed Endpoint:
/login (accessed 13 times)
```

3.Detect Suspicious Activity

It is based on failed login counts. IT lists the IP addresses that have more than a specified threshold of failed login counts 

```python
suspicious activity detected	
IP Address	Failed Login Count
```

4.Output Results

Once the log file is parsed, and the analysis is completed, The script outputs the results into a CSV file.

file_name = `logs_analysis_results.csv`


## Python file `log_analysis_code.py`

This python script is designed to analyze a log file for potential security threats and traffic patterns:

i) It uses regular expressions `re` to find IP address, HTTP request endpoints, and failed login attempts

ii) The `parse_log_file()` function reads through the log file, looking for specific patterns in each line.

iii) It tracks how many times each IP address makes a request and how often each endpoint is accessed using counters 

iv) The script also counts how many failed login attempts each IP address has made.

v) If log file is not foung, it displays an error message and stops further processing.

vi) The results of the analysis ( IP request counts,most accessed endpoints and suspicious failed logins) are written to a CSV file.

vii) The script prints the analysis to the console and save the results to a CSV file named `logs_analysis_results.csv`

viii) Finally, the `main()` function arrange the entire process, calling other function and printing/saving results.











