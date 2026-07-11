import re
from collections import Counter

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
        badLineCounter = 0
        errorCounter = 0
        endpoints = Counter()
        times = Counter()
        for line in f:
            lineCounter+=1
            parsed = parse_line(line)
            if parsed:
                ips.add(parsed.get("ip"))
                endpoints[parsed.get("path")] += 1 
                times[parsed.get("time")[12:14]] += 1
                status = parsed.get("status")
                if status[0] == "4" or status[0] == "5":
                    errorCounter+=1
                continue
            badLineCounter+=1
    validLines = lineCounter - badLineCounter
    errorRate = ( errorCounter / validLines ) * 100
    print(f"Total lines: {lineCounter}")
    print(f"\nBad lines: {badLineCounter}")
    print(f"\nUnique ips: {len(ips)}")
    print("Most common endpoints")
    print(f"{"endpoint":<20} | {"count"}")
    for endpoint in endpoints.most_common(10):
        print(f"{endpoint[0]:<20} | {endpoint[1]}")
    print(f"Error rate: {errorRate:.2f}%")
    print("\nTime distribution:")
    for hour in sorted(times.keys()):
        print(f"{hour}:00 | {times[hour]}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    args = parser.parse_args()
    analyze(args.logfile)