from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

BASE_URL = "https://cvedb.shodan.io/cve"

def fetch_cve_details(cve):
    url = f"{BASE_URL}/{cve}"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        # Process and return CVE details
        epss_percentage = round(data.get('epss', 0) * 100, 2)
        ranking_epss_percentage = round(data.get('ranking_epss', 0) * 100, 2)

        return {
            "cve_id": data.get('cve_id', 'N/A'),
            "summary": data.get('summary', 'N/A'),
            "cvss_version": data.get('cvss_version', 'N/A'),
            "cvss_v2": data.get('cvss_v2', 'N/A'),
            "cvss_v3": data.get('cvss_v3', 'N/A'),
            "epss": epss_percentage,
            "ranking_epss": ranking_epss_percentage,
            "references": data.get('references', []),
            "published_time": data.get('published_time', 'N/A')
        }

    except requests.RequestException:
        return {"error": f"Failed to retrieve data for CVE: {cve}. Please check the CVE identifier and try again."}

@app.route('/')
def home():
    return "CVE Lookup API is running!"

@app.route('/get_cve', methods=['POST'])
def get_cve():
    data = request.json
    cve = data.get("cve_number")

    if not cve:
        return jsonify({"error": "CVE number is required"}), 400

    result = fetch_cve_details(cve)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
