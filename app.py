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

# Disable warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# --- Configuration ---
# AES Key and IV for payload encryption. Fetched from environment variables or uses default.
KEY = os.getenv('AES_KEY', 'Yg&tc%DEuh6%Zc^8').encode()
IV = os.getenv('AES_IV', '6oyZDr22E3ychjM%').encode()

# --- Account Credentials ---
# Stores UID and Password for each region's guest account
ACCOUNTS = {
    'IND': {'uid': '3930873969', 'password': 'A7C2C6D4626074C70B978141C03D39350887BD4928D5E7CC9D86BE8B22269BC0'},
    'SG': {'uid': '3158350464', 'password': '70EA041FCF79190E3D0A8F3CA95CAAE1F39782696CE9D85C2CCD525E28D223FC'},
    'RU': {'uid': '3301239795', 'password': 'DD40EE772FCBD61409BB15033E3DE1B1C54EDA83B75DF0CDD24C34C7C8798475'},
    'ID': {'uid': '3301269321', 'password': 'D11732AC9BBED0DED65D0FED7728CA8DFF408E174202ECF1939E328EA3E94356'},
    'TW': {'uid': '3301329477', 'password': '359FB179CD92C9C1A2A917293666B96972EF8A5FC43B5D9D61A2434DD3D7D0BC'},
    'US': {'uid': '3301387397', 'password': 'BAC03CCF677F8772473A09870B6228ADFBC1F503BF59C8D05746DE451AD67128'},
    'VN': {'uid': '3301447047', 'password': '044714F5B9284F3661FB09E4E9833327488B45255EC9E0CCD953050E3DEF1F54'},
    'TH': {'uid': '3301470613', 'password': '39EFD9979BD6E9CCF6CBFF09F224C4B663E88B7093657CB3D4A6F3615DDE057A'},
    'ME': {'uid': '3301535568', 'password': 'BEC9F99733AC7B1FB139DB3803F90A7E78757B0BE395E0A6FE3A520AF77E0517'},
    'PK': {'uid': '3301828218', 'password': '3A0E972E57E9EDC39DC4830E3D486DBFB5DA7C52A4E8B0B8F3F9DC4450899571'},
    'CIS': {'uid': '3309128798', 'password': '412F68B618A8FAEDCCE289121AC4695C0046D2E45DB07EE512B4B3516DDA8B0F'},
    'BR': {'uid': '3158668455', 'password': '44296D19343151B25DE68286BDC565904A0DA5A5CC5E96B7A7ADBE7C11E07933'},
    'BD': {'uid': '4019945507', 'password': 'C812B81009FF4DF135D4DC19883C0FAA887AD2CB489306BBFE5DB7C5703B5B61'}
}

# --- Server URLs ---
# Maps region codes to their corresponding game server endpoints
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
    """Retrieves account credentials for a given region."""
    return ACCOUNTS.get(region.upper())

def get_server_url(region: str) -> Optional[str]:
    """Retrieves the game server URL for a given region."""
    return REGION_URLS.get(region.upper())

async def fetch_token(region: str) -> Dict:
    """
    Asynchronously fetches a JWT token from the specified API for a given region.
    This function has been UPDATED to use the new token service.
    """
    if region not in VALID_REGIONS:
        raise ValueError(f"Invalid region: {region}")
    
    credentials = get_account_credentials(region)
    if not credentials:
        raise ValueError(f"No credentials for region: {region}")
    
    # --- MODIFIED PART ---
    # Using the new JWT token API endpoint as requested.
    url = f"https://atx-jwt-pi.vercel.app/token?uid={credentials['uid']}"
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            # Raise an exception for bad status codes (4xx or 5xx)
            response.raise_for_status()
            data = await response.json()
            
            # Extract the token from the response. Assumes the key is 'token'.
            token = data.get('token')
            if not token:
                error_message = data.get('error', 'Token not found in the response from JWT service')
                raise ValueError(f"Failed to get JWT token: {error_message}")
            
            return {
                'token': token,
                'lockRegion': region
            }
    # --- END OF MODIFIED PART ---

def build_payload(lang: str = "en") -> bytes:
    """Builds the protobuf payload for the LoginGetSplash request."""
    b = bytearray()
    b += b'\x0a' + bytes([len(lang)]) + lang.encode()
    b += b'\x10\x02'
    b += b'\x18\x01'
    return bytes(b)

def encrypt_payload(data: bytes) -> str:
    """Encrypts the payload using AES-CBC and returns a hex string."""
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    return binascii.hexlify(encrypted_data).decode()

def transform(proto_resp: splash_pb2.SplashResponse, requested_region: str, served_region: str) -> Dict:
    """Transforms the protobuf response into a structured JSON dictionary."""
    out = {
        "events": [],
        "region": served_region,
        "success": True,
        "source": "API by ATX" # A little credit
    }

    def is_valid_link(link: str) -> bool:
        """Checks if a string is a valid HTTP/HTTPS URL."""
        return link and link.strip().startswith(('http://', 'https://')) and len(link.strip()) > 10

    # Process 'updates' from the protobuf response
    for item in proto_resp.updates.items:
        upd = {
            "type": "update",
            "Banner": item.Banner,
            "Details": item.Details.strip(),
            "Start": item.Start,
            "End": item.End,
            "Title": item.Title,
        }
        # Find the first valid link
        for link in [item.Link, item.LinkAlt]:
            if is_valid_link(link):
                upd["link"] = link.strip()
                break
        out["events"].append(upd)

    # Process 'events' from the protobuf response
    for item in proto_resp.events.items:
        evt = {
            "type": "event",
            "Banner": item.Banner,
            "Start": item.Start,
            "End": item.End,
            "Title": item.Title or item.TitleAlt,
        }
        if is_valid_link(item.Link):
            evt["link"] = item.Link.strip()
        out["events"].append(evt)

    return out

@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "message": "API is running. Use /event endpoint.",
        "usage": "/event?region=IND&lang=en",
        "valid_regions": list(VALID_REGIONS),
        "author": "ATX"
    })

@app.route("/event")
def get_event_data():
    """Main API endpoint to fetch event data."""
    region = request.args.get("region", "IND").upper()
    lang = request.args.get("lang", "en")

    try:
        # 1. Validate Region
        if region not in VALID_REGIONS:
            return jsonify({
                "success": False,
                "error": f"Invalid region. Valid regions are: {', '.join(VALID_REGIONS)}"
            }), 400

        # 2. Fetch JWT Token using the new service
        token_data = asyncio.run(fetch_token(region))
        if not token_data or 'token' not in token_data:
            return jsonify({"success": False, "error": "Token fetch failed"}), 500

        token = token_data['token']
        actual_region = token_data.get('lockRegion', region)
        server_url = get_server_url(actual_region)
        if not server_url:
            return jsonify({"success": False, "error": f"No server URL for region: {actual_region}"}), 500

        # 3. Prepare Request Headers
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB49" # You might need to update this for future game versions
        }

        # 4. Build and Encrypt Payload
        payload = build_payload(lang)
        encrypted_payload_hex = encrypt_payload(payload)

        # 5. Make Request to Game Server
        response = requests.post(
            server_url,
            data=bytes.fromhex(encrypted_payload_hex),
            headers=headers,
            verify=False  # Disables SSL certificate verification
        )
        response.raise_for_status() # Raise an exception for HTTP errors

        # 6. Parse Protobuf Response
        proto_resp = splash_pb2.SplashResponse()
        proto_resp.ParseFromString(response.content)

        # 7. Transform and Return JSON
        result = transform(proto_resp, requested_region=region, served_region=actual_region)
        return jsonify(result)

    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except aiohttp.ClientError as e:
        return jsonify({"success": False, "error": f"Failed to fetch token: {str(e)}"}), 502
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": f"Request to game server failed: {str(e)}"}), 502
    except Exception as e:
        # Log the full error for debugging
        app.logger.error(f"An unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": "An internal server error occurred."}), 500

if __name__ == "__main__":
    # Get port from environment variable or default to 5000
    port = int(os.getenv('PORT', 5000))
    # Get debug mode from environment variable
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')
    app.run(debug=debug_mode, host='0.0.0.0', port=port)
