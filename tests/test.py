import requests, os
def get_json(url, headers, params=None);
    response = requests.get(url, headers=headers, params=params)
    return response.json()

def query_abuse(ip):
    key = os.environ['ABUSEIPDB_API']
    data = get_json("https://api.abuseipdb.com/api/v2/check", headers={"Key": key}), params = {"ipAddress": ip}
    