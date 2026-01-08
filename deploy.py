import json
import os
from web3 import Web3
from dotenv import load_dotenv

load_dotenv()

GANACHE_URL = os.getenv("GANACHE_URL", "http://127.0.0.1:7545")
ABI_PATH = os.path.join(os.path.dirname(__file__), "truffle/build/contracts/AuthChain.json")

def deploy():
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    if not w3.is_connected():
        print("Error: Cannot connect to Ganache")
        return

    if not os.path.exists(ABI_PATH):
        print(f"Error: Artifact not found at {ABI_PATH}. Run 'truffle compile' first.")
        return

    with open(ABI_PATH, "r") as f:
        artifact = json.load(f)

    abi = artifact["abi"]
    bytecode = artifact["bytecode"]

    w3.eth.default_account = w3.eth.accounts[0]
    print(f"Deploying from account: {w3.eth.default_account}")

    AuthChain = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx_hash = AuthChain.constructor().transact()
    
    print("Waiting for transaction to be mined...")
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print("-" * 30)
    print(f"Contract Deployed At: {tx_receipt.contractAddress}")
    print("-" * 30)

    # --- AUTO-UPDATE .ENV ---
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    new_line = f"CONTRACT_ADDRESS={tx_receipt.contractAddress}\n"
    
    lines = []
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            lines = f.readlines()
            
    updated = False
    with open(env_path, "w") as f:
        for line in lines:
            if line.startswith("CONTRACT_ADDRESS="):
                f.write(new_line)
                updated = True
            else:
                f.write(line)
        if not updated:
            if lines and not lines[-1].endswith("\n"):
                f.write("\n")
            f.write(new_line)
            
    print(f"Updated .env with new CONTRACT_ADDRESS: {tx_receipt.contractAddress}")

if __name__ == "__main__":
    deploy()
