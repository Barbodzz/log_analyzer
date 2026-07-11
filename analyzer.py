import re
from collections import Counter
import argparse

PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>.+)\] \"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)\" (?P<status>\d+) (?P<size>\d+) \"-\" \"(?P<user_agent>.+)\"'
)
BAR = '\u2588'

def parse_line(line):
    match = PATTERN.match(line)
    if match:
        return match.groupdict()
    return None

def is_error(status):
    return status[0] in ("4", "5") 


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
                times[parsed.get("time")[12:14]] += 1 # extract hour (index 12:14)
                status = parsed.get("status")
                if is_error(status):
                    errorCounter+=1
                continue
            badLineCounter+=1 # malformed line, skip and count


    validLines = lineCounter - badLineCounter
    errorRate = ( errorCounter / validLines ) * 100

    print(f"Total lines: {lineCounter}")
    print(f"\nBad lines: {badLineCounter}")
    print(f"\nValid lines: {validLines}")
    print(f"\nUnique ips: {len(ips)}")
    print("\nMost common endpoints")
    header_ep = "endpoint"
    header_c = "count"
    print(f"{header_ep:<20} | {header_c}")
    for endpoint in endpoints.most_common(10):
        print(f"{endpoint[0]:<20} | {endpoint[1]}")
    print(f"\nError rate: {errorRate:.2f}%")
    print("\nTime distribution:")
    for hour in sorted(times.keys()):
        print(f"{hour}:00 | {times[hour]}")
    print("Time distribution chart")
    maxValue = max(times.values())
    scale = maxValue / 25
    for hour in sorted(times.keys()):
        print(f"{hour}:00 | {BAR * int(times[hour] / scale)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    args = parser.parse_args()
    analyze(args.logfile)