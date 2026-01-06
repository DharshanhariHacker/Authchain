from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS, cross_origin
from web3 import Web3
from eth_account.messages import encode_defunct
import time
import os
import uuid
import hashlib
from functools import wraps
import jwt 
from werkzeug.utils import secure_filename
from cachelib import SimpleCache
from dotenv import load_dotenv
import json 


load_dotenv()

GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "0x6cd5B60Bd7CEfDA8D716E909Ed7d77b43ef53C76") 
CONTRACT_ABI_PATH = os.path.join(os.path.dirname(__file__), "truffle/build/contracts/AuthChain.json")


JWT_SECRET = os.getenv("JWT_SECRET", "my_super_strong_and_very_long_secret_key_123!")
JWT_EXP_SECONDS = 3600


NONCE_EXP_SECONDS = 300
TOKEN_EXP_SECONDS = 3600 



nonce_cache = SimpleCache(threshold=1000, default_timeout=NONCE_EXP_SECONDS)
token_blocklist = SimpleCache(threshold=2000, default_timeout=TOKEN_EXP_SECONDS)
login_history_store = {} # {address: [(timestamp, ip), ...]}
asset_store = {} # {asset_id: {owner, type, status, description, registered_at}}

# --- Security: Rate Limiting Setup ---
request_history = {}
RATE_LIMIT_WINDOW = 60  # seconds
MAX_REQUESTS = 10       # max requests per IP per window
LAST_CLEANUP = time.time()
CLEANUP_INTERVAL = 300 # Clean up stale entries every 5 minutes

def rate_limit(f):
    """
    Decorator to limit the rate of requests from a single IP.
    Prevents brute-force and DoS attacks on sensitive endpoints.
    Includes memory leak protection by cleaning up stale IPs.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        global LAST_CLEANUP
        ip = request.remote_addr
        now = time.time()
        
        # Periodic cleanup of stale entries to prevent memory leak
        if now - LAST_CLEANUP > CLEANUP_INTERVAL:
            to_remove = []
            for stored_ip, timestamps in request_history.items():
                # Keep if at least one timestamp is within the window
                if not any(now - t < RATE_LIMIT_WINDOW for t in timestamps):
                    to_remove.append(stored_ip)
            for key in to_remove:
                del request_history[key]
            LAST_CLEANUP = now

        # Clean up old timestamps for current IP and check limit
        history = request_history.get(ip, [])
        history = [t for t in history if now - t < RATE_LIMIT_WINDOW]
        
        if len(history) >= MAX_REQUESTS:
            request_history[ip] = history # Update with cleaned list
            return jsonify({"error": "Too many requests. Please try again later."}), 429
            
        history.append(now)
        request_history[ip] = history
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "*", "allow_headers": ["Content-Type", "Authorization"]}})

w3 = Web3(Web3.HTTPProvider(GANACHE_URL))


@app.after_request
def add_security_headers(response):
    """Add HTTP headers to protect against common browser vulnerabilities."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response


if not w3.is_connected():
    print(f"ERROR: Cannot connect to Ganache at {GANACHE_URL}.")
    print("Please ensure Ganache (or your Ethereum node) is running and GANACHE_URL is set correctly.")
    exit(1)
else:
    print(f"Successfully connected to Ethereum node at {GANACHE_URL}")

if not os.path.exists(CONTRACT_ABI_PATH):
    print(f"ERROR: Contract ABI file not found at {CONTRACT_ABI_PATH}.")
    print("Have you compiled your contract? Try running: cd truffle && truffle compile")
    exit(1)

with open(CONTRACT_ABI_PATH, "r") as f:
    try:
        contract_json = json.load(f)
        contract_abi = contract_json.get("abi")
    except json.JSONDecodeError:
        print(f"ERROR: Could not decode JSON from {CONTRACT_ABI_PATH}.")
        exit(1)

if not contract_abi:
    print("="*50)
    print(f"WARNING: 'abi' key not found or is empty in {CONTRACT_ABI_PATH}.")
    print("Please populate AuthChain.json with your contract's ABI.")
    print("Backend will run, but contract calls will fail.")
    print("="*50)


contract = None
if not CONTRACT_ADDRESS or not Web3.is_address(CONTRACT_ADDRESS):
    print(f"WARNING: CONTRACT_ADDRESS '{CONTRACT_ADDRESS}' is not set or is not a valid Ethereum address.")
    print("Please set the CONTRACT_ADDRESS in your .env file.")
elif not contract_abi:
    print("WARNING: Cannot initialize contract object because ABI is missing.")
else:
    try:
        checksum_address = Web3.to_checksum_address(CONTRACT_ADDRESS)
        contract = w3.eth.contract(address=checksum_address, abi=contract_abi)
        print(f"Successfully initialized contract at {CONTRACT_ADDRESS}")
    except Exception as e:
        print(f"WARNING: Could not initialize contract at {CONTRACT_ADDRESS}. Error: {e}")
        print("Ensure GANACHE_URL, CONTRACT_ADDRESS, and AuthChain.json are correct.")



def jwt_required(f):
    """
    A decorator to protect routes with JWT authentication.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({"error": "Malformed Authorization header. Use 'Bearer <token>'"}), 401

        if not token:
            return jsonify({"error": "Missing authentication token"}), 401

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            # Check if token is invalid (blocklisted)
            jti = payload.get("jti")
            if jti and token_blocklist.get(jti):
                return jsonify({"error": "Token has been revoked"}), 401

            current_user_address = payload['sub']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(current_user_address, *args, **kwargs)
    return decorated_function



@app.route('/')
@cross_origin() 
def index():
    return send_from_directory('.', 'index.html')

@app.route('/index.html')
@cross_origin() 
def index_html():
    return send_from_directory('.', 'index.html')

@app.route('/dashboard.html')
@cross_origin() 
def dashboard():
    return send_from_directory('.', 'dashboard.html')

@app.route('/verify-asset.html')
@cross_origin() 
def verify_page():
    return send_from_directory('.', 'verify-asset.html')

@app.route('/admin.html')
@cross_origin() 
def admin_page():
    return send_from_directory('.', 'admin.html')


@app.route("/challenge", methods=["POST"])
@cross_origin() 
@rate_limit
def get_challenge():
    if not contract:
        return jsonify({"error": "Backend server is not configured correctly. Check contract details."}), 500

    data = request.json or {}
    address = data.get("address")
    if not address:
        return jsonify({"error": "Provide 'address' in body"}), 400
    
    try:
        address = Web3.to_checksum_address(address)
    except ValueError:
        return jsonify({"error": "Invalid 'address' format"}), 400

    try:
        is_active = contract.functions.isUserActive(address).call()
        
    except Exception as e:
        print(f"Contract call error for isUserActive({address}): {e}")
        return jsonify({"error": "Contract call failed."}), 500
    
    if not is_active:
        return jsonify({"error": "Address not registered or inactive on-chain"}), 403
    
    nonce = f"AuthChain login challenge:{address}:{int(time.time())}:{os.urandom(8).hex()}"
    nonce_cache.set(address, nonce)
    print(f"Generated challenge for {address}")
    return jsonify({"address": address, "nonce": nonce})

@app.route("/verify", methods=["POST"])
@cross_origin() 
@rate_limit
def verify():
    if not contract:
        return jsonify({"error": "Backend server is not configured correctly. Check contract details."}), 500

    data = request.json or {}
    address = data.get("address")
    signature = data.get("signature")
    
    if not address or not signature:
        return jsonify({"error": "Need 'address' and 'signature' in body"}), 400

    try:
        address = Web3.to_checksum_address(address)
    except ValueError:
        return jsonify({"error": "Invalid 'address' format"}), 400

    nonce = nonce_cache.get(address)
    if not nonce:
        return jsonify({"error": "No nonce found for address. Request /challenge first."}), 400

    message = encode_defunct(text=nonce)
    try:
        recovered = w3.eth.account.recover_message(message, signature=signature)
    except Exception as e:
        print(f"Signature recovery failed: {e}")
        return jsonify({"error": "Signature recovery failed"}), 400

    if Web3.to_checksum_address(recovered) != address:
        print(f"Signature mismatch. Expected {address}, got {recovered}")
        return jsonify({"error": "Signature does not match address"}), 403

    try:
        is_active = contract.functions.isUserActive(address).call()
    except Exception as e:
        return jsonify({"error": "Contract call failed"}), 500
    
    if not is_active:
        return jsonify({"error": "User is no longer active on-chain"}), 403

    payload = {
        "sub": address,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXP_SECONDS,
        "jti": os.urandom(16).hex() # Unique ID for revocation
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    
    # --- Login History Logic ---
    client_ip = request.remote_addr
    now = int(time.time())
    user_history = login_history_store.get(address, [])
    # Keep last 5 logins
    user_history.insert(0, {"ip": client_ip, "time": now})
    user_history = user_history[:5]
    login_history_store[address] = user_history

    nonce_cache.delete(address)
    print(f"Verified {address}, issued JWT. IP: {client_ip}")

    return jsonify({
        "status": "success", 
        "token": token, 
        "history": user_history
    })

@app.route("/status/<address>", methods=["GET"])
@cross_origin() 
def status(address):
    if not contract:
        return jsonify({"error": "Backend server is not configured correctly. Check contract details."}), 500

    try:
        address = Web3.to_checksum_address(address)
    except ValueError:
        return jsonify({"error": "Invalid address"}), 400
    
    try:
        active = contract.functions.isUserActive(address).call()
    except Exception as e:
        return jsonify({"error": "Contract call failed"}), 500
    
    return jsonify({"address": address, "isActive": active})

@app.route("/config", methods=["GET"])
@cross_origin()
def get_config():
    """Returns public configuration like contract address."""
    return jsonify({
        "contractAddress": CONTRACT_ADDRESS,
        "networkId": "5777" # Default Ganache ID
    })

@app.route("/protected")
@cross_origin() 
@jwt_required
def protected(current_user_address):
    """
    An example of a protected endpoint.
    The `current_user_address` is passed by the `jwt_required` decorator.
    """
    print(f"User {current_user_address} accessed protected route.")
    return jsonify(message=f"Welcome {current_user_address}!", detail="You are accessing a protected resource.")

@app.route("/logout", methods=["POST"])
@cross_origin()
@jwt_required
def logout(current_user_address):
    """
    Revokes the current user's token adds it to the blocklist.
    """
    token = None
    if 'Authorization' in request.headers:
        token = request.headers['Authorization'].split(" ")[1]
    
    if token:
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            jti = payload.get("jti")
            if jti:
                # Add to blocklist for remaining lifetime
                exp = payload.get("exp")
                ttl = exp - int(time.time())
                if ttl > 0:
                    token_blocklist.set(jti, "revoked", timeout=ttl)
                print(f"Token revoked for user {current_user_address}")
        except Exception:
            pass # Ignore invalid tokens during logout
            
    return jsonify({"status": "success", "message": "Logged out successfully."})

@app.route("/api/assets/register", methods=["POST"])
@cross_origin()
@jwt_required
def register_asset(current_user_address):
    """Register a new physical asset on-chain."""
    # Handle Form Data instead of JSON
    id_ = request.form.get("id")
    type_ = request.form.get("type", "Asset") # Now treating as 'Category'
    desc = request.form.get("description")
    
    if not id_ or not desc:
        return jsonify({"error": "Missing 'id' or 'description'"}), 400

    # Handle File Upload (Proof)
    proof_hash = ""
    image_url = ""
    
    if 'proof' in request.files:
        file = request.files['proof']
        if file.filename != '':
            # Calculate SHA256 Hash
            file_bytes = file.read()
            proof_hash = hashlib.sha256(file_bytes).hexdigest()
            
            # Save File Locally
            filename = secure_filename(f"{id_}_{file.filename}")
            upload_dir = os.path.join(app.static_folder, 'uploads')
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)
            
            file_path = os.path.join(upload_dir, filename)
            # Reset pointer to start to save it
            file.seek(0) 
            file.save(file_path)
            
            # Use relative path for frontend
            image_url = f"/static/uploads/{filename}"

    # Generate Asset ID (if not provided, though form provides it usually)
    # The 'type' prompt asked for category, so let's use it as category.
    # We'll use the id_ passed from frontend.
    
    try:
        # Check if ID exists
        try:
            exists = contract.functions.getAsset(id_).call()
            return jsonify({"error": "Asset ID already exists"}), 400
        except Exception as e:
            # This exception means the asset doesn't exist, which is good.
            # A more robust check would be to check the error message or specific error type.
            # For now, we assume any error means it doesn't exist.
            pass 

        # Register on Blockchain (V4)
        # registerAsset(id, desc, category, proofHash, imageUrl, owner)
        tx_hash = contract.functions.registerAsset(
            id_, 
            desc, 
            type_,      # Sending 'Type' as 'Category'
            proof_hash, 
            image_url, 
            current_user_address
        ).transact({'from': w3.eth.accounts[0]})
        
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Asset {id_} registered by {current_user_address} (Hash: {proof_hash})")
        
    except Exception as e:
        print(f"Blockchain Error: {e}")
        return jsonify({"error": str(e)}), 500

    return jsonify({"status": "success", "tx_hash": tx_hash.hex()})

@app.route("/api/assets/list", methods=["GET"])
@cross_origin()
@jwt_required
def list_assets(current_user_address):
    """List assets owned by the user."""
    user_assets = []
    
    # ITERATE ON-CHAIN ASSETS (Inefficient for Mainnet, OK for Prototype)
    try:
        count = contract.functions.getAssetCount().call()
        print(f"DEBUG: Found {count} total assets on-chain.")
        for i in range(count):
             aid = contract.functions.assetIds(i).call()
             details = contract.functions.getAsset(aid).call()
             # details: (id, desc, status, owner, regAt)
             
             on_chain_owner = str(details[3])
             print(f"DEBUG: Checking Asset {aid} (Owner: {on_chain_owner}) vs User {current_user_address}")

             # Case-insensitive comparison is safer
             if on_chain_owner.lower() == current_user_address.lower(): 
                 parts = details[1].split(" | ", 1)
                 atype = parts[0] if len(parts) > 1 else "Asset"
                 adesc = parts[1] if len(parts) > 1 else details[1]
                 
                 user_assets.append({
                    "id": details[0],
                    "type": atype,
                    "description": adesc,
                    "status": details[2],
                    "registered_at": details[4]
                 })
    except Exception as e:
        print(f"Listing Error: {e}")
        return jsonify({"error": "Failed to fetch assets"}), 500

    return jsonify({"assets": user_assets, "user": current_user_address})


@app.route("/api/admin/stolen", methods=["GET"])
@cross_origin()
def admin_stolen_feed():
    """Admin endpoint to list all stolen assets (No Auth for Demo Context)."""
    stolen_assets = []
    
    try:
        count = contract.functions.getAssetCount().call()
        for i in range(count):
             aid = contract.functions.assetIds(i).call()
             details = contract.functions.getAsset(aid).call()
             # details: (id, desc, status, owner, regAt)
             
             status = details[2]
             if status == "STOLEN":
                parts = details[1].split(" | ", 1)
                atype = parts[0] if len(parts) > 1 else "Asset"
                adesc = parts[1] if len(parts) > 1 else details[1]
                 
                stolen_assets.append({
                    "id": details[0],
                    "type": atype,
                    "description": adesc,
                    "status": status,
                    "owner": str(details[3])
                })
    except Exception as e:
        print(f"Admin Scan Error: {e}")
        return jsonify({"error": "Failed to scan blockchain"}), 500

    return jsonify({"assets": stolen_assets})


@app.route("/api/assets/report", methods=["POST"])
@cross_origin()
@jwt_required
def report_asset(current_user_address):
    """Report an asset as stolen or recover it."""
    data = request.json or {}
    asset_id = data.get("asset_id")
    status = data.get("status") # STOLEN or CLEAN
    
    if not asset_id or status not in ["STOLEN", "CLEAN"]:
        return jsonify({"error": "Invalid request"}), 400
        
    asset = None
    try:
        details = contract.functions.getAsset(asset_id).call()
        asset_owner = details[3]
        if asset_owner != current_user_address:
            return jsonify({"error": "Unauthorized"}), 403
            
        # Send Tx
        tx_hash = contract.functions.setAssetStatus(asset_id, status).transact({'from': w3.eth.accounts[0]})
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Asset {asset_id} status updated to {status} on-chain.")
        
    except Exception as e:
        print(f"Report Error: {e}")
        return jsonify({"error": "Blockchain Error or Asset Not Found"}), 500

    return jsonify({"status": "success"})

@app.route("/api/assets/transfer", methods=["POST"])
@cross_origin()
@jwt_required
def transfer_asset(current_user_address):
    """Transfer an asset to another user."""
    data = request.json or {}
    asset_id = data.get("asset_id")
    new_owner = data.get("new_owner")
    
    if not asset_id or not new_owner:
        return jsonify({"error": "Missing asset_id or new_owner"}), 400
        
    if new_owner.lower() == current_user_address.lower():
        return jsonify({"error": "Cannot transfer to yourself"}), 400
        
    try:
        new_owner = Web3.to_checksum_address(new_owner)
    except ValueError:
        return jsonify({"error": "Invalid new owner address"}), 400

    try:
        details = contract.functions.getAsset(asset_id).call()
        current_owner = details[3]
        
        # Case Insensitive Check
        if str(current_owner).lower() != current_user_address.lower():
            return jsonify({"error": "You do not own this asset"}), 403
            
        # Send Transfer Tx (Gov Node pays gas)
        tx_hash = contract.functions.transferAsset(asset_id, new_owner).transact({'from': w3.eth.accounts[0]})
        w3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Asset {asset_id} transferred from {current_user_address} to {new_owner}")
        
    except Exception as e:
        print(f"Transfer Error: {e}")
        return jsonify({"error": "Blockchain Error: " + str(e)}), 500

    return jsonify({"status": "success"})

@app.route("/api/verify-asset/<asset_id>", methods=["GET"])
@cross_origin()
def verify_asset(asset_id):
    """Public endpoint to verify asset status (Anonymous)."""
    try:
        details = contract.functions.getAsset(asset_id).call()
        
        parts = details[1].split(" | ", 1)
        atype = parts[0] if len(parts) > 1 else "Asset"
        adesc = parts[1] if len(parts) > 1 else details[1]
        
        # --- FETCH HISTORY (LOGS) ---
        history = []
        try:
            # Create a filter for AssetTransfer events for this specific ID
            event_filter = contract.events.AssetTransfer.create_filter(from_block=0, argument_filters={'id': asset_id})
            logs = event_filter.get_all_entries()
            
            for log in logs:
                args = log['args']
                history.append({
                    "from": args['from'],
                    "to": args['to'],
                    "timestamp": args['timestamp'],
                    "tx_hash": log['transactionHash'].hex()
                })
                
            # Sort by timestamp descending (newest first)
            history.sort(key=lambda x: x['timestamp'], reverse=True)
            
        except Exception as e:
            print(f"Log Fetch Error: {e}")
            # Non-critical, return empty history if fails
            
        return jsonify({
            "id": details[0],
            "type": atype,
            "description": adesc,
            "status": details[2],
            "is_stolen": details[2] == "STOLEN",
            "proofHash": details[6],
            "imageUrl": details[7],
            "history": history
        })
    except Exception:
        return jsonify({"error": "Asset not found"}), 404



if __name__ == "__main__":
    print(f"Starting Flask server at http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)