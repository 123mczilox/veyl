from url_parser import analyze_message_urls


message = """
URGENT: Your account will be blocked!
Verify your details at http://192.0.2.10/login
or visit www.example.com.
"""

results = analyze_message_urls(message)

print("URL ANALYSIS RESULTS")
print("=" * 40)

if not results:
    print("No URLs found.")

for result in results:
    print(f"\nURL: {result['url']}")
    print(f"Hostname: {result['hostname']}")
    print(f"Findings: {result['findings']}")
    print(f"Risk indicators: {result['risk_indicators']}")
