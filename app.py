from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

BASE_URL = "https://api.first.org/data/v1/epss"

def fetch_epss_data(cve, date):
    """
    Fetch EPSS data from the API for a specific CVE and date.

    Parameters:
        cve (str): The CVE identifier (e.g., CVE-2022-26332).
        date (str): The date in YYYY-MM-DD format.

    Returns:
        dict: The JSON response from the API or an error message.
    """
    url = f"{BASE_URL}?envelope=true&pretty=true&cve={cve}&date={date}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        # If no data is found
        if not data["data"]:
            return {"error": f"The CVE {cve} is not in the EPSS repository."}

        # Extract relevant fields
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

@app.route('/get_epss', methods=['POST'])
def get_epss():
    data = request.json
    cve = data.get("cve")
    date = data.get("date")

    if not cve or not date:
        return jsonify({"error": "Both CVE number and date are required"}), 400

    result = fetch_epss_data(cve, date)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
