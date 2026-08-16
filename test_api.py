from threat_api import scan_url, wait_for_analysis, get_stats


url = "https://google.com"

print("Scanning URL...")

scan_result = scan_url(url)

analysis_id = scan_result["data"]["id"]

print("Analysis ID:", analysis_id)

result = wait_for_analysis(analysis_id)

if result is None:
    print("Analysis did not complete within the allowed time.")
else:
    stats = get_stats(result)

    print("\nVirusTotal Stats:")
    print("Malicious:", stats["malicious"])
    print("Suspicious:", stats["suspicious"])
    print("Harmless:", stats["harmless"])
    print("Undetected:", stats["undetected"])