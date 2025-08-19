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
from typing import Dict, Optional, Any

app = Flask(__name__)
urllib3.disable_warnings()

# =========================
# 🔐 AES Config (ENV থাকলে সেখান থেকে নেবে)
# =========================
KEY = os.getenv('AES_KEY', 'Yg&tc%DEuh6%Zc^8').encode()
IV  = os.getenv('AES_IV',  '6oyZDr22E3ychjM%').encode()

# =========================
# 👤 Region-wise লগইন অ্যাকাউন্ট
# =========================
ACCOUNTS = {
    'IND': {'uid': '3930873969', 'password': 'A7C2C6D4626074C70B978141C03D39350887BD4928D5E7CC9D86BE8B22269BC0'},
    'SG' : {'uid': '4118759390', 'password': '0FA823E6AC97A1E935C413D04B05F98E3B3449311A62936B6380E018D3CFFDE2'},
    'RU' : {'uid': '3301239795', 'password': 'DD40EE772FCBD61409BB15033E3DE1B1C54EDA83B75DF0CDD24C34C7C8798475'},
    'ID' : {'uid': '3301269321', 'password': 'D11732AC9BBED0DED65D0FED7728CA8DFF408E174202ECF1939E328EA3E94356'},
    'TW' : {'uid': '3301329477', 'password': '359FB179CD92C9C1A2A917293666B96972EF8A5FC43B5D9D61A2434DD3D7D0BC'},
    'US' : {'uid': '3301387397', 'password': 'BAC03CCF677F8772473A09870B6228ADFBC1F503BF59C8D05746DE451AD67128'},
    'VN' : {'uid': '3301447047', 'password': '044714F5B9284F3661FB09E4E9833327488B45255EC9E0CCD953050E3DEF1F54'},
    'TH' : {'uid': '3301470613', 'password': '39EFD9979BD6E9CCF6CBFF09F224C4B663E88B7093657CB3D4A6F3615DDE057A'},
    'ME' : {'uid': '3301535568', 'password': 'BEC9F99733AC7B1FB139DB3803F90A7E78757B0BE395E0A6FE3A520AF77E0517'},
    'PK' : {'uid': '4118749794', 'password': 'B74BBDE04CA48D110FA08826B9300A3F429FCA80FAA02F81EB27607250533E01'},
    'CIS': {'uid': '3309128798', 'password': '412F68B618A8FAEDCCE289121AC4695C0046D2E45DB07EE512B4B3516DDA8B0F'},
    'BR' : {'uid': '3158668455', 'password': '44296D19343151B25DE68286BDC565904A0DA5A5CC5E96B7A7ADBE7C11E07933'},
    'BD' : {'uid': '4019945507', 'password': 'C812B81009FF4DF135D4DC19883C0FAA887AD2CB489306BBFE5DB7C5703B5B61'}
}

# =========================
# 🌍 Region → Server URL
# =========================
REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com/LoginGetSplash",
    "ID" : "https://clientbp.ggblueshark.com/LoginGetSplash",
    "BR" : "https://client.us.freefiremobile.com/LoginGetSplash",
    "ME" : "https://clientbp.common.ggbluefox.com/LoginGetSplash",
    "VN" : "https://clientbp.common.ggbluefox.com/LoginGetSplash",
    "TH" : "https://clientbp.common.ggbluefox.com/LoginGetSplash",
    "CIS": "https://clientbp.common.ggbluefox.com/LoginGetSplash",
    "BD" : "https://clientbp.ggblueshark.com/LoginGetSplash",
    "PK" : "https://clientbp.ggblueshark.com/LoginGetSplash",
    "SG" : "https://clientbp.ggblueshark.com/LoginGetSplash",
    "NA" : "https://client.us.freefiremobile.com/LoginGetSplash",
    "SAC": "https://client.us.freefiremobile.com/LoginGetSplash",
    "EU" : "https://clientbp.ggblueshark.com/LoginGetSplash",
    "TW" : "https://clientbp.ggblueshark.com/LoginGetSplash"
}

VALID_REGIONS = set(ACCOUNTS.keys())

def get_account_credentials(region: str) -> Optional[Dict]:
    return ACCOUNTS.get(region.upper())

def get_server_url(region: str) -> Optional[str]:
    return REGION_URLS.get(region.upper())

# =========================
# 🔑 JWT Fetch (নতুন API)
# =========================
async def fetch_token(region: str) -> Dict:
    if region not in VALID_REGIONS:
        raise ValueError(f"Invalid region: {region}")
    creds = get_account_credentials(region)
    if not creds:
        raise ValueError(f"No credentials for region: {region}")

    url = (
        "https://garenaunlimitedgwt.vercel.app/token"
        f"?uid={creds['uid']}&password={creds['password']}"
    )

    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            resp.raise_for_status()
            data = await resp.json()
            if not data.get('token'):
                raise ValueError("Failed to get JWT token")
            return {
                'token': data['token'],
                # API তে 'server' থাকলে সেটাই আসল সার্ভড রিজিয়ন
                'lockRegion': data.get('server', region)
            }

# =========================
# 🧱 Request Payload Build + Encrypt
# =========================
def build_payload(lang: str = "en") -> bytes:
    # proto-lite: field 1 (string lang), field 2 (int 2), field 3 (int 1)
    b = bytearray()
    b += b'\x0a' + bytes([len(lang)]) + lang.encode()
    b += b'\x10\x02'
    b += b'\x18\x01'
    return bytes(b)

def encrypt_payload(data: bytes) -> str:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    enc = cipher.encrypt(pad(data, AES.block_size))
    return binascii.hexlify(enc).decode()

# =========================
# 🧹 Utilities (ডুপ্লিকেট হ্যান্ডলিং/সর্টিং)
# =========================
def _is_valid_link(link: str) -> bool:
    if not link:
        return False
    s = link.strip()
    return (s.startswith('http://') or s.startswith('https://')) and len(s) > 10

def _clean_text(x: Any) -> str:
    try:
        return str(x or '').strip()
    except Exception:
        return ''

def _parse_ts(val: Any) -> int:
    """
    Start/End সাধারণত ইন্ট/টাইমস্ট্যাম্প। কোন কারণে স্ট্রিং এলে:
    - pure digit হলে int নেবে,
    - না হলে 0 (unknown)।
    """
    if val is None:
        return 0
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        s = val.strip()
        if s.isdigit():
            return int(s)
    # অজানা ফরম্যাট হলে 0
    return 0

def _dedup_and_sort(items: list) -> list:
    """
    ডুপ্লিকেট রিমুভ: key = (normalized_title, banner)
    একই key এর মধ্যে যার Start বেশি (লেটেস্ট) সেটাই রাখা হবে।
    এরপর Start DESC অর্ডারে সর্ট করে রিটার্ন।
    """
    by_key = {}
    for it in items:
        title = _clean_text(it.get('Title') or it.get('title'))
        banner = _clean_text(it.get('Banner'))
        start_ts = _parse_ts(it.get('Start'))
        key = (title.lower(), banner)

        prev = by_key.get(key)
        if (prev is None) or (_parse_ts(prev.get('Start')) < start_ts):
            by_key[key] = it

    # sort by Start desc
    out = sorted(by_key.values(), key=lambda x: _parse_ts(x.get('Start')), reverse=True)
    return out

# =========================
# 🔁 Transform Proto → JSON (ডুপ্লিকেট ফ্রি + লেটেস্ট ডেট)
# =========================
def transform(proto_resp, requested_region: str, served_region: str) -> Dict:
    collected = []

    # updates.items
    for item in proto_resp.updates.items:
        upd = {
            "Banner": item.Banner,
            "Details": _clean_text(getattr(item, 'Details', '')),
            "Start": _parse_ts(getattr(item, 'Start', 0)),
            "End":   _parse_ts(getattr(item, 'End', 0)),
            "Title": _clean_text(getattr(item, 'Title', '')),
        }

        # Link / LinkAlt থেকে প্রথম বৈধটা নেবে
        link = _clean_text(getattr(item, 'Link', ''))
        link_alt = _clean_text(getattr(item, 'LinkAlt', ''))
        if _is_valid_link(link):
            upd["link"] = link
        elif _is_valid_link(link_alt):
            upd["link"] = link_alt

        collected.append(upd)

    # events.items
    for item in proto_resp.events.items:
        title = _clean_text(getattr(item, 'Title', '')) or _clean_text(getattr(item, 'TitleAlt', ''))
        evt = {
            "Banner": item.Banner,
            "Start":  _parse_ts(getattr(item, 'Start', 0)),
            "End":    _parse_ts(getattr(item, 'End', 0)),
            "Title":  title,
        }
        link = _clean_text(getattr(item, 'Link', ''))
        if _is_valid_link(link):
            evt["link"] = link

        collected.append(evt)

    # ✅ ডুপ্লিকেট রিমুভ + Start DESC
    final_events = _dedup_and_sort(collected)

    return {
        "events": final_events,
        "region": served_region,
        "requestedRegion": requested_region,
        "success": True,
        "count": len(final_events)
    }

# =========================
# 🌐 API Route
# =========================
@app.route("/event")
def get_event_data():
    region = request.args.get("region", "IND").upper()
    lang   = request.args.get("lang", "en")

    try:
        if region not in VALID_REGIONS:
            return jsonify({
                "success": False,
                "error": f"Invalid region. Valid regions are: {', '.join(sorted(VALID_REGIONS))}"
            }), 400

        token_data = asyncio.run(fetch_token(region))
        if not token_data or 'token' not in token_data:
            return jsonify({"success": False, "error": "Token fetch failed"}), 500

        token = token_data['token']
        actual_region = token_data.get('lockRegion', region).upper()
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

        resp = requests.post(
            server_url,
            data=bytes.fromhex(enc_payload),
            headers=headers,
            verify=False,
            timeout=25
        )
        resp.raise_for_status()

        proto_resp = splash_pb2.SplashResponse()
        proto_resp.ParseFromString(resp.content)

        result = transform(proto_resp, requested_region=region, served_region=actual_region)
        return jsonify(result)

    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except requests.exceptions.RequestException as e:
        return jsonify({"success": False, "error": f"Request failed: {str(e)}"}), 502
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500

# =========================
# ▶️ Run
# =========================
if __name__ == "__main__":
    app.run(
        debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
        port=int(os.getenv('PORT', 5000)),
        host="0.0.0.0"
    )
