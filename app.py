from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)

# Allow CORS for all origins (Adjust this if needed)
CORS(app, resources={r"/*": {"origins": "*"}})

BASE_URL = "https://api.first.org/data/v1/epss"

def fetch_epss_data(cve, date):
    """
    Fetch EPSS data from the API for a specific CVE and date.
    """
    url = f"{BASE_URL}?cve={cve}&date={date}"

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if not data["data"]:
            return {"error": f"The CVE {cve} is not in the EPSS repository."}

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
        response = jsonify(result)
        response.headers.add("Access-Control-Allow-Origin", "*")
        return response

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
