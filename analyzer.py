import re

PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>.+)\] \"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)\" (?P<status>\d+) (?P<size>\d+) \"-\" \"(?P<user_agent>.+)\"'
)
def parse_line(line):
    match = PATTERN.match(line)
    if match:
        return match.groupdict()
    return None


def analyze(filePath):
    with open(filePath) as f:
        ips = set()
        lineCounter = 0
        errorCounter = 0
        for line in f:
            lineCounter+=1
            parsed = parse_line(line)
            if parsed:
                ips.add(parsed.get("ip"))
                continue
            errorCounter+=1
    print(f"Total lines: {lineCounter}")
    print(f"Bad lines: {errorCounter}")
    print(f"Unique ips: {len(ips)}")



analyze("/Users/barbodzz/Downloads/hamamooz_task/access.log")