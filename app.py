from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS, cross_origin # Import cross_origin for route-specific CORS
from web3 import Web3
from eth_account.messages import encode_defunct
from cachelib import SimpleCache
import os
import time
from functools import wraps
from dotenv import load_dotenv
import jwt
import json 

# Load environment variables from a .env file if it exists.
load_dotenv()

# --- Configuration ---
# URL for your Ethereum node (e.g., Ganache, Infura)
GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")

# Deployed contract address
# The default is just a placeholder, your .env file will override this.
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "0xE571b5b1eeB4a56EB830d225260AE13757a5C285") 

# Path to your contract's ABI JSON file
# It looks in the 'truffle' subfolder relative to this script.
CONTRACT_ABI_PATH = os.path.join(os.path.dirname(__file__), "truffle/build/contracts/AuthChain.json")

# Secret for signing JWTs.
JWT_SECRET = os.getenv("JWT_SECRET", "my_super_strong_and_very_long_secret_key_123!")
JWT_EXP_SECONDS = 3600

# Nonce expiration time in seconds
NONCE_EXP_SECONDS = 300
# --- End Configuration ---

# Use a cache for nonces.
nonce_cache = SimpleCache(threshold=1000, default_timeout=NONCE_EXP_SECONDS)
app = Flask(__name__)
# Set up CORS explicitly to allow Content-Type and Authorization headers
CORS(app, resources={r"/*": {"origins": "*", "allow_headers": ["Content-Type", "Authorization"]}})

w3 = Web3(Web3.HTTPProvider(GANACHE_URL))

# --- Startup Checks ---
if not w3.is_connected():
    print(f"ERROR: Cannot connect to Ganache at {GANACHE_URL}.")
    print("Please ensure Ganache (or your Ethereum node) is running and GANACHE_URL is set correctly.")
    exit(1)
else:
    print(f"Successfully connected to Ethereum node at {GANACHE_URL}")

# Load contract ABI
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

# Initialize contract
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
# --- End Startup Checks ---


def jwt_required(f):
    """
    A decorator to protect routes with JWT authentication.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        # Check for token in the Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                # Header should be: "Bearer <token>"
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({"error": "Malformed Authorization header. Use 'Bearer <token>'"}), 401

        if not token:
            return jsonify({"error": "Missing authentication token"}), 401

        try:
            # Decode the token. This also verifies the signature and expiration.
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user_address = payload['sub']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(current_user_address, *args, **kwargs)
    return decorated_function

# --- Public Routes ---

@app.route('/')
@cross_origin() # Add CORS support
def index():
    # Serve the index.html file from the current directory
    return send_from_directory('.', 'index.html')

@app.route('/index.html')
@cross_origin() # Add CORS support
def index_html():
    # Serve the index.html file from the current directory
    return send_from_directory('.', 'index.html')


@app.route("/challenge", methods=["POST"])
@cross_origin() # Add CORS support
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

    # Check if user is registered and active
    try:
        # --- THIS IS THE FIX ---
        # The extra dot '..' is removed.
        is_active = contract.functions.isUserActive(address).call()
        # ---------------------
    except Exception as e:
        print(f"Contract call error for isUserActive({address}): {e}")
        return jsonify({"error": "Contract call failed. Is ABI correct?", "detail": str(e)}), 500
    
    if not is_active:
        return jsonify({"error": "Address not registered or inactive on-chain"}), 403
    
    # Generate a unique, time-stamped nonce
    nonce = f"AuthChain login challenge:{address}:{int(time.time())}:{os.urandom(8).hex()}"
    nonce_cache.set(address, nonce)
    print(f"Generated challenge for {address}")
    return jsonify({"address": address, "nonce": nonce})

@app.route("/verify", methods=["POST"])
@cross_origin() # Add CORS support
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
        return jsonify({"error": "Signature recovery failed", "detail": str(e)}), 400

    if Web3.to_checksum_address(recovered) != address:
        print(f"Signature mismatch. Expected {address}, got {recovered}")
        return jsonify({"error": "Signature does not match address"}), 403

    # Final check on-chain
    try:
        is_active = contract.functions.isUserActive(address).call()
    except Exception as e:
        return jsonify({"error": "Contract call failed", "detail": str(e)}), 500
    
    if not is_active:
        return jsonify({"error": "User is no longer active on-chain"}), 403

    # All good: issue JWT
    payload = {
        "sub": address,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXP_SECONDS
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    
    # Clear nonce after successful use
    nonce_cache.delete(address)
    print(f"Verified {address}, issued JWT.")
    return jsonify({"status": "success", "token": token})

@app.route("/status/<address>", methods=["GET"])
@cross_origin() # Add CORS support
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
        return jsonify({"error": "Contract call failed", "detail": str(e)}), 500
    
    return jsonify({"address": address, "isActive": active})

# --- Protected Routes ---

@app.route("/protected")
@cross_origin() # Add CORS support
@jwt_required
def protected(current_user_address):
    """
    An example of a protected endpoint.
    The `current_user_address` is passed by the `jwt_required` decorator.
    """
    print(f"User {current_user_address} accessed protected route.")
    return jsonify(message=f"Welcome {current_user_address}!", detail="You are accessing a protected resource.")

# --- Server Runner ---

if __name__ == "__main__":
    # Quick-start development server
    print(f"Starting Flask server at http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)