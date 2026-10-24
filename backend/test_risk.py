from url_parser import analyze_message_urls
from risk_engine import calculate_risk

message = """
URGENT: Your M-Pesa account will be suspended today!
Verify your PIN immediately at http://192.0.2.10/login
"""

url_results = analyze_message_urls(message)

result = calculate_risk(message, url_results)

print("SCAMSHIELD RISK ASSESSMENT")
print("=" * 40)
print(f"Risk score: {result['score']}")
print(f"Risk level: {result['risk_level']}")

print("\nEvidence:")

for item in result["evidence"]:
    print(f"- {item}")
