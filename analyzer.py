import re

PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>.+)\] \"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)\" (?P<status>\d+) (?P<size>\d+) \"-\" \"(?P<user_agent>.+)\"'
)
def parse_line(line):
    match = PATTERN.match(line)
    if match:
        return match.groupdict()
    return None

line = '64.142.139.54 - - [01/Jun/2026:00:00:00 +0000] "GET /products HTTP/1.1" 200 11390 "-" "curl/8.4.0"'
print(parse_line(line))