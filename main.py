import hashlib
import json
import time
import random
import requests
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from collections import OrderedDict
from typing import List, Dict
from flask import Flask, jsonify, request
import threading

# --------- Blockchain Classes ---------

class Block:
    def __init__(self, index: int, timestamp: float, data: Dict, previous_hash: str, hash: str, validator: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = hash
        self.validator = validator

    def __repr__(self):
        return f"Block(index={self.index}, hash={self.hash[:10]}, validator={self.validator[:10]})"


class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []
        self.transactions: List[Dict] = []
        self.nodes = set()
        self.create_genesis_block()

    def create_genesis_block(self):
        """Create the first block in the blockchain (genesis block)."""
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            data={"transactions": []},
            previous_hash="0",
            hash=self.calculate_hash(0, "0", time.time(), {"transactions": []}, "0"),
            validator="0"
        )
        self.chain.append(genesis_block)

    def calculate_hash(self, index: int, previous_hash: str, timestamp: float, data: Dict, validator: str) -> str:
        """Calculate the hash of a block using its contents."""
        block_string = json.dumps(
            OrderedDict({
                "index": index,
                "previous_hash": previous_hash,
                "timestamp": timestamp,
                "data": data,
                "validator": validator
            }), sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def add_transaction(self, sender: str, recipient: str, amount: float, signature: str):
        """Add a transaction to the pool of pending transactions."""
        if self.validate_transaction(sender, recipient, amount, signature):
            self.transactions.append({
                "sender": sender,
                "recipient": recipient,
                "amount": amount,
                "signature": signature
            })
        else:
            print("Invalid transaction signature!")

    def validate_transaction(self, sender: str, recipient: str, amount: float, signature: str) -> bool:
        """Validate the transaction using the sender's public key."""
        public_key = self.get_public_key(sender)
        if public_key:
            transaction_data = f"{sender}{recipient}{amount}"
            return self.verify_signature(public_key, signature, transaction_data)
        return False

    def verify_signature(self, public_key: str, signature: str, data: str) -> bool:
        """Verify the digital signature of a transaction."""
        try:
            verifying_key = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
            return verifying_key.verify(bytes.fromhex(signature), data.encode())
        except:
            return False

    def get_public_key(self, address: str) -> str:
        """Get the public key from the address (for simplicity, using address as public key here)."""
        # In a real application, you'd map addresses to actual public keys, but for simplicity, 
        # we'll treat addresses as public keys directly.
        return address

    def mine_block(self, validator: str) -> Block:
        """Mine a new block using Proof of Stake mechanism."""
        last_block = self.chain[-1]
        index = last_block.index + 1
        timestamp = time.time()
        previous_hash = last_block.hash
        data = {"transactions": self.transactions}
        hash = self.calculate_hash(index, previous_hash, timestamp, data, validator)

        new_block = Block(index, timestamp, data, previous_hash, hash, validator)
        self.chain.append(new_block)
        self.transactions = []  # Clear transaction pool after mining
        return new_block

    def add_node(self, node: str):
        """Add a new node to the network."""
        self.nodes.add(node)

    def get_last_block(self) -> Block:
        """Get the last block in the blockchain."""
        return self.chain[-1]


# --------- Wallet & Cryptography ---------

class Wallet:
    def __init__(self):
        """Create a new wallet with a public/private key pair."""
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key().to_string().hex()

    def sign_transaction(self, transaction_data: str) -> str:
        """Sign a transaction with the private key."""
        return self.private_key.sign(transaction_data.encode()).hex()


# --------- P2P Network ---------

class PeerToPeerNetwork:
    def __init__(self, blockchain: Blockchain):
        self.blockchain = blockchain
        self.peers = set()

    def register_peer(self, peer_address: str):
        """Register a new peer to the network."""
        self.peers.add(peer_address)

    def broadcast_transaction(self, transaction: Dict):
        """Broadcast a new transaction to the network."""
        for peer in self.peers:
            requests.post(f"http://{peer}/transactions", json=transaction)

    def broadcast_block(self, block: Block):
        """Broadcast a new block to the network."""
        for peer in self.peers:
            requests.post(f"http://{peer}/blocks", json=block.__dict__)

    def start_server(self, host='127.0.0.1', port=5000):
        """Start a simple Flask server for P2P communication."""
        app = Flask(__name__)

        @app.route('/transactions', methods=['POST'])
        def add_transaction():
            transaction = request.get_json()
            sender = transaction['sender']
            recipient = transaction['recipient']
            amount = transaction['amount']
            signature = transaction['signature']
            self.blockchain.add_transaction(sender, recipient, amount, signature)
            return jsonify({"message": "Transaction added"}), 201

        @app.route('/blocks', methods=['POST'])
        def add_block():
            block_data = request.get_json()
            new_block = Block(**block_data)
            self.blockchain.chain.append(new_block)
            return jsonify({"message": "Block added"}), 201

        app.run(host=host, port=port)


# --------- Main Script ---------

if __name__ == "__main__":
    # Step 1: Initialize Blockchain and Peer Network
    my_blockchain = Blockchain()
    my_network = PeerToPeerNetwork(my_blockchain)

    # Step 2: Create a Wallet for each user
    alice_wallet = Wallet()
    bob_wallet = Wallet()

    # Step 3: Alice creates a transaction and signs it
    transaction_data = f"AliceBob100"
    alice_signature = alice_wallet.sign_transaction(transaction_data)
    my_blockchain.add_transaction("Alice", "Bob", 100, alice_signature)

    # Step 4: Alice mines a block
    validator = alice_wallet.public_key
    new_block = my_blockchain.mine_block(validator)
    print(f"New Block Mined: {new_block}")

    # Step 5: Start Peer-to-Peer Network Server
    server_thread = threading.Thread(target=my_network.start_server)
    server_thread.start()

    # Step 6: Register some nodes (for simplicity, we just use localhost)
    my_network.register_peer('127.0.0.1:5001')
    my_network.register_peer('127.0.0.1:5002')
