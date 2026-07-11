# Log Analyzer
A CLI tool to analyze Apache/Nginx access logs.

## Usage
**Requirements:** Python 3.6+

```bash
python3 analyzer.py /path/to/access.log
```

**Example:**
```bash
python3 analyzer.py /home/user/logs/access.log
```

## Output 
- Total lines
- Bad lines 
- Valid lines
- Unique IPs
- Top 10 endpoints with most traffic
- Error rate (4xx/5xx)
- Hourly request distribution with ASCII histogram
- Suspicious IPs (failed login attempts above threshold)

## Design Decisions 
### Parsing
Used regex to parse each log line due to the structured Combined Log Format. 
Simple `split()` was not suitable since fields like timestamp and user-agent 
contain spaces internally.
### Counting
Used `Counter` from Python's built-in `collections` library to count 
endpoint hits and hourly requests. It handles missing keys automatically 
and provides `most_common(n)` for sorted results without extra sorting logic.
### Streaming
The log file is processed line-by-line instead of loading it entirely into 
memory, making it suitable for large files.
### Suspicious Activity Detection
Tracks IPs with excessive 401 responses on `/login`. 
A fixed threshold of 50 was chosen since brute force attacks 
typically generate hundreds of attempts, making relative 
statistical methods unreliable on sparse data.

## Challenges
For counting endpoints, I initially tried using a plain dictionary — storing 
endpoints as keys and request counts as values. The issue was handling missing 
keys every time a new endpoint appeared. After consulting Claude, I discovered 
`Counter` from Python's `collections` library which handles this automatically.

For suspicious IP detection, I initially tried using the 95th percentile 
of failed login counts as a dynamic threshold. However, since the data is 
sparse (most IPs have zero failed logins), the percentile calculation was 
unreliable. I switched to a fixed threshold of 50, which is more appropriate 
for detecting brute force attacks.