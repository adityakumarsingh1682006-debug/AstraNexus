"""AstraNexus On-Chain Threat Registry Client.

Handles interaction with the EVM ThreatRegistry smart contract:
- Report commitment registration
- Revision history querying
- Dispute filing and retrieval
- Tamper-evident verification

STRICT HONESTY POLICY:
- Never fabricates transaction hashes or simulated proofs.
- If RPC node is unavailable, returns honest RPC_UNAVAILABLE status.
- If not configured, returns honest NOT_CONFIGURED status.
- Protects private keys; never exposes credentials in telemetry or logs.
"""

import logging
from enum import Enum
from typing import Dict, Any, Optional
from web3 import Web3
from web3.exceptions import Web3Exception
from eth_account import Account

try:
    from backend.app.core.config import settings
except ImportError:
    from app.core.config import settings

logger = logging.getLogger(__name__)


class BlockchainRegistrationStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    PENDING = "PENDING"
    FAILED = "FAILED"
    RPC_UNAVAILABLE = "RPC_UNAVAILABLE"
    NOT_CONFIGURED = "NOT_CONFIGURED"
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    DUPLICATE = "DUPLICATE"


class ThreatAttestationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    CONFIRMED_THREAT = "CONFIRMED_THREAT"
    BENIGN_CLEARED = "BENIGN_CLEARED"
    DISPUTED = "DISPUTED"
    REVOKED = "REVOKED"


STATUS_CODE_TO_ENUM = {
    0: ThreatAttestationStatus.UNVERIFIED,
    1: ThreatAttestationStatus.CONFIRMED_THREAT,
    2: ThreatAttestationStatus.BENIGN_CLEARED,
    3: ThreatAttestationStatus.DISPUTED,
    4: ThreatAttestationStatus.REVOKED,
}


# Minimal Application Binary Interface (ABI) for ThreatRegistry contract
THREAT_REGISTRY_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportId", "type": "bytes32"},
            {"internalType": "bytes32", "name": "commitmentHash", "type": "bytes32"}
        ],
        "name": "registerReport",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportId", "type": "bytes32"},
            {"internalType": "bytes32", "name": "newCommitmentHash", "type": "bytes32"}
        ],
        "name": "reviseReport",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportId", "type": "bytes32"},
            {"internalType": "bytes32", "name": "reasonHash", "type": "bytes32"}
        ],
        "name": "disputeReport",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportId", "type": "bytes32"},
            {"internalType": "uint8", "name": "newStatus", "type": "uint8"}
        ],
        "name": "attestReport",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "", "type": "bytes32"}],
        "name": "reports",
        "outputs": [
            {"internalType": "bytes32", "name": "reportId", "type": "bytes32"},
            {"internalType": "bytes32", "name": "commitmentHash", "type": "bytes32"},
            {"internalType": "uint256", "name": "initialTimestamp", "type": "uint256"},
            {"internalType": "address", "name": "reporter", "type": "address"},
            {"internalType": "uint8", "name": "status", "type": "uint8"},
            {"internalType": "uint256", "name": "disputeCount", "type": "uint256"},
            {"internalType": "bool", "name": "exists", "type": "bool"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "reportId", "type": "bytes32"}],
        "name": "getRevisionCount",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportId", "type": "bytes32"},
            {"internalType": "uint256", "name": "index", "type": "uint256"}
        ],
        "name": "getRevision",
        "outputs": [
            {"internalType": "bytes32", "name": "commitmentHash", "type": "bytes32"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "uint256", "name": "blockNumber", "type": "uint256"},
            {"internalType": "address", "name": "revisedBy", "type": "address"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "bytes32", "name": "reportId", "type": "bytes32"}],
        "name": "getDisputeCount",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "bytes32", "name": "reportId", "type": "bytes32"},
            {"internalType": "uint256", "name": "index", "type": "uint256"}
        ],
        "name": "getDispute",
        "outputs": [
            {"internalType": "address", "name": "disputer", "type": "address"},
            {"internalType": "bytes32", "name": "reasonHash", "type": "bytes32"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]


class ThreatRegistryClient:
    def __init__(
        self,
        rpc_url: Optional[str] = None,
        contract_address: Optional[str] = None,
        private_key: Optional[str] = None,
    ):
        self.rpc_url = rpc_url or settings.EVM_RPC_URL
        self.contract_address = contract_address or settings.ASTRA_REGISTRY_CONTRACT_ADDRESS
        self.private_key = private_key or settings.NOTARY_SIGNER_PRIVATE_KEY

        self._web3: Optional[Web3] = None
        self._contract = None
        self._account = None

    def _get_web3(self) -> Optional[Web3]:
        """Initializes Web3 provider with lazy connection check."""
        if not self.rpc_url:
            return None
        if self._web3 is None:
            self._web3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 5}))
        return self._web3

    def is_connected(self) -> bool:
        """Checks whether the RPC node is currently reachable."""
        try:
            w3 = self._get_web3()
            return bool(w3 and w3.is_connected())
        except Exception as e:
            logger.warning(f"Failed to connect to EVM RPC node: {e}")
            return False

    def _get_contract(self):
        """Initializes the Contract instance."""
        w3 = self._get_web3()
        if not w3 or not self.contract_address:
            return None
        if self._contract is None:
            checksum_address = Web3.to_checksum_address(self.contract_address)
            self._contract = w3.eth.contract(address=checksum_address, abi=THREAT_REGISTRY_ABI)
        return self._contract

    def register_report(
        self,
        report_id: str,
        commitment_hash: str,
    ) -> Dict[str, Any]:
        """Registers a report commitment on the EVM ThreatRegistry smart contract."""
        # 1. Configuration check
        if not self.rpc_url or not self.contract_address or not self.private_key:
            return {
                "status": BlockchainRegistrationStatus.NOT_CONFIGURED.value,
                "is_registered": False,
                "message": "Blockchain notary environment variables (EVM_RPC_URL, ASTRA_REGISTRY_CONTRACT_ADDRESS, NOTARY_SIGNER_PRIVATE_KEY) not fully configured.",
                "tx_hash": None,
                "report_id": report_id,
                "commitment_hash": commitment_hash,
            }

        w3 = self._get_web3()
        if not w3 or not self.is_connected():
            return {
                "status": BlockchainRegistrationStatus.RPC_UNAVAILABLE.value,
                "is_registered": False,
                "message": f"EVM RPC node at {self.rpc_url} is unreachable.",
                "tx_hash": None,
                "report_id": report_id,
                "commitment_hash": commitment_hash,
            }

        contract = self._get_contract()
        if not contract:
            return {
                "status": BlockchainRegistrationStatus.FAILED.value,
                "is_registered": False,
                "message": "Failed to instantiate ThreatRegistry contract.",
                "tx_hash": None,
                "report_id": report_id,
                "commitment_hash": commitment_hash,
            }

        # 2. Convert identifiers to bytes32 format
        try:
            if report_id.startswith("0x") and len(report_id) == 66:
                report_id_bytes = bytes.fromhex(report_id[2:])
            else:
                report_id_bytes = Web3.keccak(text=report_id)

            if commitment_hash.startswith("0x") and len(commitment_hash) == 66:
                commitment_bytes = bytes.fromhex(commitment_hash[2:])
            else:
                commitment_bytes = bytes.fromhex(commitment_hash)
        except Exception as e:
            return {
                "status": BlockchainRegistrationStatus.FAILED.value,
                "is_registered": False,
                "message": f"Invalid bytes32 commitment format: {str(e)}",
                "tx_hash": None,
                "report_id": report_id,
                "commitment_hash": commitment_hash,
            }

        # 3. Check for existing on-chain registration (Duplicate prevention)
        try:
            existing = contract.functions.reports(report_id_bytes).call()
            # existing = (reportId, commitmentHash, initialTimestamp, reporter, status, disputeCount, exists)
            if existing[6]:  # exists
                return {
                    "status": BlockchainRegistrationStatus.DUPLICATE.value,
                    "is_registered": True,
                    "message": "Report commitment already registered on-chain.",
                    "report_id": report_id,
                    "commitment_hash": "0x" + existing[1].hex(),
                    "initial_timestamp": existing[2],
                    "reporter": existing[3],
                    "attestation_status": STATUS_CODE_TO_ENUM.get(existing[4], ThreatAttestationStatus.UNVERIFIED).value,
                    "dispute_count": existing[5],
                    "tx_hash": None,
                }
        except Exception as e:
            logger.warning(f"Pre-check for existing report failed: {e}")

        # 4. Prepare and sign transaction
        try:
            account = Account.from_key(self.private_key)
            sender_address = account.address
            balance = w3.eth.get_balance(sender_address)

            # Gas estimation
            nonce = w3.eth.get_transaction_count(sender_address)
            gas_price = w3.eth.gas_price

            tx_func = contract.functions.registerReport(report_id_bytes, commitment_bytes)
            try:
                estimated_gas = tx_func.estimate_gas({"from": sender_address})
            except Exception:
                estimated_gas = 150000

            gas_cost = estimated_gas * gas_price
            if balance < gas_cost:
                return {
                    "status": BlockchainRegistrationStatus.INSUFFICIENT_FUNDS.value,
                    "is_registered": False,
                    "message": f"Account {sender_address} balance ({w3.from_wei(balance, 'ether')} ETH) insufficient for estimated gas ({w3.from_wei(gas_cost, 'ether')} ETH).",
                    "tx_hash": None,
                    "report_id": report_id,
                    "commitment_hash": commitment_hash,
                }

            tx = tx_func.build_transaction({
                "from": sender_address,
                "nonce": nonce,
                "gas": int(estimated_gas * 1.2),
                "gasPrice": gas_price,
            })

            signed_tx = w3.eth.account.sign_transaction(tx, private_key=self.private_key)
            tx_hash_bytes = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
            tx_hash_hex = tx_hash_bytes.hex()
            if not tx_hash_hex.startswith("0x"):
                tx_hash_hex = "0x" + tx_hash_hex

            # Wait for receipt
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash_bytes, timeout=20)
            if receipt.status == 1:
                return {
                    "status": BlockchainRegistrationStatus.CONFIRMED.value,
                    "is_registered": True,
                    "message": "Report commitment successfully written to blockchain.",
                    "tx_hash": tx_hash_hex,
                    "block_number": receipt.blockNumber,
                    "gas_used": receipt.gasUsed,
                    "report_id": report_id,
                    "commitment_hash": commitment_hash,
                    "network": f"Chain ID {w3.eth.chain_id}",
                    "contract_address": self.contract_address,
                }
            else:
                return {
                    "status": BlockchainRegistrationStatus.FAILED.value,
                    "is_registered": False,
                    "message": "Transaction reverted on-chain.",
                    "tx_hash": tx_hash_hex,
                    "report_id": report_id,
                    "commitment_hash": commitment_hash,
                }

        except Exception as e:
            logger.error(f"Failed to broadcast registration transaction: {e}")
            return {
                "status": BlockchainRegistrationStatus.FAILED.value,
                "is_registered": False,
                "message": f"Transaction execution failed: {str(e)}",
                "tx_hash": None,
                "report_id": report_id,
                "commitment_hash": commitment_hash,
            }

    def verify_report(self, report_id: str, expected_commitment_hash: str) -> Dict[str, Any]:
        """Queries on-chain registry to verify if a report's commitment matches expected payload."""
        if not self.rpc_url or not self.contract_address:
            return {
                "is_verified": False,
                "exists": False,
                "status": "UNAVAILABLE",
                "message": "Blockchain notary configuration unavailable.",
            }

        w3 = self._get_web3()
        if not w3 or not self.is_connected():
            return {
                "is_verified": False,
                "exists": False,
                "status": "RPC_UNAVAILABLE",
                "message": "Unable to connect to blockchain node for verification.",
            }

        contract = self._get_contract()
        if not contract:
            return {
                "is_verified": False,
                "exists": False,
                "status": "ERROR",
                "message": "Contract instance unavailable.",
            }

        try:
            if report_id.startswith("0x") and len(report_id) == 66:
                report_id_bytes = bytes.fromhex(report_id[2:])
            else:
                report_id_bytes = Web3.keccak(text=report_id)

            record = contract.functions.reports(report_id_bytes).call()
            # record = (reportId, commitmentHash, initialTimestamp, reporter, status, disputeCount, exists)
            exists = record[6]
            if not exists:
                return {
                    "is_verified": False,
                    "exists": False,
                    "status": "NOT_REGISTERED",
                    "message": "No on-chain commitment registered for this report identifier.",
                }

            on_chain_hash = "0x" + record[1].hex()
            expected_clean = expected_commitment_hash.lower()
            if not expected_clean.startswith("0x"):
                expected_clean = "0x" + expected_clean

            is_match = on_chain_hash.lower() == expected_clean
            return {
                "is_verified": is_match,
                "exists": True,
                "status": "TAMPER_EVIDENT_VERIFIED" if is_match else "COMMITMENT_MISMATCH",
                "on_chain_commitment": on_chain_hash,
                "expected_commitment": expected_clean,
                "initial_timestamp": record[2],
                "reporter": record[3],
                "attestation_status": STATUS_CODE_TO_ENUM.get(record[4], ThreatAttestationStatus.UNVERIFIED).value,
                "dispute_count": record[5],
                "contract_address": self.contract_address,
                "network": f"Chain ID {w3.eth.chain_id}",
            }
        except Exception as e:
            return {
                "is_verified": False,
                "exists": False,
                "status": "QUERY_FAILED",
                "message": f"Failed to query on-chain report: {str(e)}",
            }


threat_registry_client = ThreatRegistryClient()
