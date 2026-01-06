import json
import os
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
# Path to the compiled JSON from 'truffle compile'
ABI_PATH = os.path.join(os.path.dirname(__file__), "truffle/build/contracts/AuthChain.json")

def deploy():
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if not w3.is_connected():
        print("Error: Cannot connect to Ganache")
        return

    # 1. Read the compiled artifact
    if not os.path.exists(ABI_PATH):
        print(f"Error: Artifact not found at {ABI_PATH}. Run 'truffle compile' first.")
        return

    with open(ABI_PATH, "r") as f:
        artifact = json.load(f)

    abi = artifact["abi"]
    bytecode = artifact["bytecode"]

    # 2. Get Account (first one)
    w3.eth.default_account = w3.eth.accounts[0]
    print(f"Deploying from account: {w3.eth.default_account}")

    # 3. Instantiate and Deploy
    AuthChain = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = AuthChain.constructor().transact()
    
    print("Waiting for transaction to be mined...")
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print("-" * 30)
    print(f"Contract Deployed At: {tx_receipt.contractAddress}")
    print("-" * 30)

if __name__ == "__main__":
    deploy()
