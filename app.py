from flask import Flask, request, jsonify
import requests
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import splash_pb2
import urllib3
import aiohttp
import asyncio
import os
from typing import Dict, Optional

app = Flask(__name__)
urllib3.disable_warnings()

# Configuration
KEY = os.getenv('AES_KEY', 'Yg&tc%DEuh6%Zc^8').encode()
IV = os.getenv('AES_IV', '6oyZDr22E3ychjM%').encode()

# Account credentials
ACCOUNTS = {
    'IND': {'uid': '3930873969', 'password': 'A7C2C6D4626074C70B978141C03D39350887BD4928D5E7CC9D86BE8B22269BC0'},
    'SG': {'uid': '3894723299', 'password': '479A07BBD3822FC6FB60EC983B58A1DC9D4132BF4FE55F02531511E738D51E51'},
    'RU': {'uid': '3301239795', 'password': 'DD40EE772FCBD61409BB15033E3DE1B1C54EDA83B75DF0CDD24C34C7C8798475'},
    'ID': {'uid': '3301269321', 'password': 'D11732AC9BBED0DED65D0FED7728CA8DFF408E174202ECF1939E328EA3E94356'},
    'TW': {'uid': '3301329477', 'password': '359FB179CD92C9C1A2A917293666B96972EF8A5FC43B5D9D61A2434DD3D7D0BC'},
    'US': {'uid': '3301387397', 'password': 'BAC03CCF677F8772473A09870B6228ADFBC1F503BF59C8D05746DE451AD67128'},
    'VN': {'uid': '3301447047', 'password': '044714F5B9284F3661FB09E4E9833327488B45255EC9E0CCD953050E3DEF1F54'},
    'TH': {'uid': '3301470613', 'password': '39EFD9979BD6E9CCF6CBFF09F224C4B663E88B7093657CB3D4A6F3615DDE057A'},
    'ME': {'uid': '3301535568', 'password': 'BEC9F99733AC7B1FB139DB3803F90A7E78757B0BE395E0A6FE3A520AF77E0517'},
    'PK': {'uid': '3894713579', 'password': 'A1CB99A09E639C5A98995BB83C73F71C09629A07CC3C6248C8C73120579A5EB7'},
    'CIS': {'uid': '3309128798', 'password': '412F68B618A8FAEDCCE289121AC4695C0046D2E45DB07EE512B4B3516DDA8B0F'},
    'BR': {'uid': '3158668455', 'password': '44296D19343151B25DE68286BDC565904A0DA5A5CC5E96B7A7ADBE7C11E07933'},
    'BD': {'uid': '4019945507', 'password': 'C812B81009FF4DF135D4DC19883C0FAA887AD2CB489306BBFE5DB7C5703B5B61'}
}

REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com/LoginGetSplash",
    "ID": "https://clientbp.ggblueshark.com/LoginGetSplash",
    "BR": "https://client.us.freefiremobile.com/LoginGetSplash",
    "ME": "https://clientbp.common.ggbluefox.com/LoginGetSplash",
    "VN": "https://clientbp.common.ggbluefox.com/LoginGetSplash",
    "TH": "https://clientbp.common.ggbluefox.com/LoginGetSplash",
    "CIS": "https://clientbp.common.ggbluefox.com/LoginGetSplash",
    "BD": "https://clientbp.ggblueshark.com/LoginGetSplash",
    "PK": "https://clientbp.ggblueshark.com/LoginGetSplash",
    "SG": "https://clientbp.ggblueshark.com/LoginGetSplash",
    "NA": "https://client.us.freefiremobile.com/LoginGetSplash",
    "SAC": "https://client.us.freefiremobile.com/LoginGetSplash",
    "EU": "https://clientbp.ggblueshark.com/LoginGetSplash",
    "TW": "https://clientbp.ggblueshark.com/LoginGetSplash"
}

VALID_REGIONS = set(ACCOUNTS.keys())

def get_account_credentials(region: str) -> Optional[Dict]:
    return ACCOUNTS.get(region.upper())

def get_server_url(region: str) -> Optional[str]:
    return REGION_URLS.get(region.upper())

# ✅ Updated API URL used here
async def fetch_token(region: str) -> Dict:
    if region not in VALID_REGIONS:
        raise ValueError(f"Invalid region: {region}")
    
    credentials = get_account_credentials(region)
    if not credentials:
        raise ValueError(f"No credentials for region: {region}")
    
    url = f"https://garenaunlimitedgwt.vercel.app/token?uid={credentials['uid']}&password={credentials['password']}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            response.raise_for_status()
            data = await response.json()
            if not data.get('token'):
                raise ValueError("Failed to get JWT token")
            return {
                'token': data['token'],
                'lockRegion': data.get('server', region)  # 'server' used in new API instead of 'region'
            }

def build_payload(lang: str = "en") -> bytes:
    b = bytearray()
    b += b'\x0a' + bytes([len(lang)]) + lang.encode()
    b += b'\x10\x02'
    b += b'\x18\x01'
    return bytes(b)

def encrypt_payload(data: bytes) -> str:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    enc = cipher.encrypt(pad(data, AES.block_size))
    return binascii.hexlify(enc).decode()

def transform(proto_resp, requested_region: str, served_region: str) -> Dict:
    out = {
        "events": [],
        "region": served_region,
        "success": True
    }

    def is_valid_link(link: str) -> bool:
        return link.strip().startswith(('http://', 'https://')) and len(link.strip()) > 10

    for item in proto_resp.updates.items:
        upd = {
            "Banner": item.Banner,
            "Details": item.Details.strip(),
            "Start": item.Start,
            "End": item.End,
            "Title": item.Title,
        }
        for link in [item.Link, item.LinkAlt]:
            if link and is_valid_link(link):
                upd["link"] = link.strip()
                break
        out["events"].append(upd)

    for item in proto_resp.events.items:
        evt = {
            "Banner": item.Banner,
            "Start": item.Start,
            "End": item.End,
            "Title": item.Title or item.TitleAlt,
        }
        if item.Link and is_valid_link(item.Link):
            evt["link"] = item.Link.strip()
        out["events"].append(evt)

    return out

@app.route("/event")
def get_event_data():
    region = request.args.get("region", "IND").upper()
    lang = request.args.get("lang", "en")

    try:
        if region not in VALID_REGIONS:
            return jsonify({
                "success": False,
                "error": f"Invalid region. Valid regions are: {', '.join(VALID_REGIONS)}"
            }), 400

        token_data = asyncio.run(fetch_token(region))
        if not token_data or 'token' not in token_data:
            return jsonify({"success": False, "error": "Token fetch failed"}), 500

        token = token_data['token']
        actual_region = token_data.get('lockRegion', region)
        server_url = get_server_url(actual_region)
        if not server_url:
            return jsonify({"success": False, "error": f"No server URL for region: {actual_region}"}), 500

        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB50"
        }

        payload = build_payload(lang)
        enc_payload = encrypt_payload(payload)

        response = requests.post(
            server_url,
            data=bytes.fromhex(enc_payload),
            headers=headers,
            verify=False
        )
        response.raise_for_status()

        proto_resp = splash_pb2.SplashResponse()
        proto_resp.ParseFromString(response.content)

        result = transform(proto_resp, requested_region=region, served_region=actual_region)
        return jsonify(result)

    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": f"Request failed: {str(e)}"}), 502
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true', port=int(os.getenv('PORT', 5000)))
