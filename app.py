from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

BASE_URL = "https://api.first.org/data/v1/epss"

def fetch_epss_data(cve, date):
    """
    Fetch EPSS data from the API for a specific CVE and date.
    """
    url = f"{BASE_URL}?cve={cve}&date={date}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if not data["data"]:
            return {
                "cve": cve,
                "date": date,
                "epss": "N/A",
                "percentile": "N/A",
                "description": "This CVE is not currently listed in the EPSS database.",
                "message": "No score available at this time."
            }

        epss = round(float(data["data"][0]["epss"]) * 100, 2)
        percentile = round(float(data["data"][0]["percentile"]) * 100, 2)

        return {
            "cve": cve,
            "date": date,
            "epss": epss,
            "percentile": percentile,
            "message": "Chance of being exploited in the next 30 days."
        }

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def fetch_cve_description(cve):
    """
    Fetch the CVE description from the NVD 1.0 API.
    """
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}"
    headers = {
        "User-Agent": "EPSS-Lookup/1.0"
    }

    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        res = requests.get(nvd_url, headers=headers, timeout=10)
        res.raise_for_status()
        data = res.json()

        descriptions = data["result"]["CVE_Items"][0]["cve"]["description"]["description_data"]
        for entry in descriptions:
            if entry["lang"] == "en":
                return entry["value"]

        return "No English description available."

    except Exception as e:
        print(f"Error fetching CVE description: {e}")
        return "Description not available"


@app.route('/')
def home():
    return "EPSS Lookup API is running!"


@app.route('/get_epss', methods=['POST', 'OPTIONS'])
def get_epss():
    if request.method == "OPTIONS":
        response = jsonify({"message": "CORS preflight successful"})
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        response.headers.add("Access-Control-Allow-Methods", "POST, OPTIONS")
        return response, 200

    if not request.is_json:
        return jsonify({"error": "Request must be in JSON format"}), 400

    try:
        data = request.get_json()
        cve = data.get("cve")
        date = data.get("date")

        if not cve or not date:
            return jsonify({"error": "Both CVE number and date are required"}), 400

        result = fetch_epss_data(cve, date)

        if "error" not in result and result.get("epss") != "N/A":
            result["description"] = fetch_cve_description(cve)

        response = jsonify(result)
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)