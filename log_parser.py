import os
import sys
import re
import json
from collections import Counter
from datetime import datetime


def parse_log_line(line):
    log_pattern = (
        r'(?P<ip>\S+)\s+-\s+-\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d+)\s+(?P<size>\S+)\s+'
        r'"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"\s+'
        r'(?P<duration>\d+)'
    )
    match = re.match(log_pattern, line)
    if match:
        return match.groupdict()
    return None


def analyze_log_file(filepath):
    print(f"\nАнализ файла: {filepath}")

    total_requests = 0
    method_counter = Counter()
    ip_counter = Counter()
    slowest_requests = []

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parsed = parse_log_line(line)
            if not parsed:
                continue

            total_requests += 1
            method_counter[parsed["method"]] += 1
            ip_counter[parsed["ip"]] += 1

            duration = int(parsed["duration"])
            slowest_requests.append(
                (duration, {
                    "ip": parsed["ip"],
                    "date": f"[{parsed['time']}]",
                    "method": parsed["method"],
                    "url": parsed["url"],
                    "duration": duration
                })
            )

    slowest_requests.sort(reverse=True, key=lambda x: x[0])
    top_longest = [req for _, req in slowest_requests[:3]]
    stats = {
        "top_ips": dict(ip_counter.most_common(3)),
        "top_longest": top_longest,
        "total_stat": dict(method_counter),
        "total_requests": total_requests
    }
    return stats


def save_stats(stats, filepath):
    base_name = os.path.splitext(os.path.basename(filepath))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"{base_name}_{timestamp}.json"

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f"Статистика сохранена в: {out_file}")


def process_path(path):
    if os.path.isfile(path):
        stats = analyze_log_file(path)
        print(json.dumps(stats, indent=2, ensure_ascii=False))
        save_stats(stats, path)
    elif os.path.isdir(path):
        for fname in os.listdir(path):
            full_path = os.path.join(path, fname)
            if os.path.isfile(full_path) and "access.log" in fname:
                stats = analyze_log_file(full_path)
                print(json.dumps(stats, indent=2, ensure_ascii=False))
                save_stats(stats, full_path)
    else:
        print(f"Указанный путь не найден: {path}")


def main():
    if len(sys.argv) < 2:
        print("Использование: python3 log_parser.py <file_or_directory>")
        sys.exit(1)

    path = sys.argv[1]
    process_path(path)


if __name__ == "__main__":
    main()
