import re
from collections import Counter
import argparse
import time
import gzip
import json



PATTERN = re.compile(
    r'(?P<ip>\S+) - - \[(?P<time>.+)\] \"(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)\" (?P<status>\d+) (?P<size>\d+) \"-\" \"(?P<user_agent>.+)\"'
)
BAR = '\u2588'
SUSPICIOUS_THRESHOLD = 50

def parse_line(line):
    match = PATTERN.match(line)
    if match:
        return match.groupdict()
    return None

def is_error(status):
    return status[0] in ("4", "5") 


def analyze(filePath, top = 10, as_json = False):
    if filePath.endswith(".gz"):
        f = gzip.open(filePath, "rt")
    else:
        f = open(filePath)
    with f:
        ips = set()
        lineCounter = 0
        badLineCounter = 0
        errorCounter = 0
        endpoints = Counter()
        times = Counter()
        failedLoginRequests = Counter()
        errors_per_hour = Counter()
        for line in f:
            lineCounter+=1
            parsed = parse_line(line)
            if parsed:
                path = parsed.get("path")
                ip = parsed.get("ip")
                ips.add(ip)
                hour = parsed.get("time")[12:14] # extract hour (index 12:14)
                endpoints[path] += 1 
                times[hour] += 1 
                status = parsed.get("status")

                if path == "/login" and status == "401":
                    failedLoginRequests[ip] += 1

                if status[0] == "5":
                    errors_per_hour[hour] += 1

                if is_error(status):
                    errorCounter+=1
                
                continue
            badLineCounter+=1 # malformed line, skip and count


    validLines = lineCounter - badLineCounter
    errorRate = ( errorCounter / validLines ) * 100

    result = {
        "total_lines": lineCounter,
        "bad_lines": badLineCounter,
        "valid_lines": validLines,
        "unique_ips": len(ips),
        "top_endpoints": endpoints.most_common(top),
        "error_rate": errorRate,
        "time_distribution": dict(sorted(times.items())),
        "suspicious_ips": {ip: count for ip, count in failedLoginRequests.items() if count > SUSPICIOUS_THRESHOLD},
    }
    if as_json:
        print(json.dumps(result, indent = 2))
    else:
        print(f"Total lines: {lineCounter}")
        print(f"\nBad lines: {badLineCounter}")
        print(f"\nValid lines: {validLines}")
        print(f"\nUnique ips: {len(ips)}")
        print("\nMost common endpoints")

        header_ep = "endpoint"
        header_c = "count"
        print(f"{header_ep:<20} | {header_c}")
        for endpoint in endpoints.most_common(top):
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

        print("Suspicious IPs")
        for ip, count in failedLoginRequests.items():
            if count > SUSPICIOUS_THRESHOLD:
                print(f"{ip} -> {count} failed login attempts")

        print("\n5xx Spike Detection:")
        averageErrors = sum(errors_per_hour.values()) / len(errors_per_hour)
        spikeThreshold = 2 * averageErrors
        for hour in sorted(errors_per_hour.keys()):
            if errors_per_hour[hour] >  spikeThreshold:
                print(f"{hour}:00 → SPIKE: {errors_per_hour[hour]} errors (avg: {averageErrors:.0f})")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile")
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    start = time.time()
    analyze(args.logfile, args.top, args.json)
    print(f"\nExecuted in {time.time() - start:.2f}s")