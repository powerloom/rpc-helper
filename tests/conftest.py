"""
Pytest configuration and shared fixtures for the RPC Helper test suite.
This module provides common test fixtures, mock objects, and configuration
used across the test suite.
"""
import asyncio
from typing import Dict, List, Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx
from web3 import AsyncWeb3
from web3.contract import AsyncContract

from rpc_helper.rpc import RpcHelper
from rpc_helper.utils.models.settings_model import RPCConfigBase, RPCNodeConfig, ConnectionLimits


# Test configuration
TEST_RPC_URL = "https://eth.llamarpc.com"
TEST_ARCHIVE_URL = "https://eth.llamarpc.com"


@pytest.fixture
def rpc_config() -> RPCConfigBase:
    """Fixture providing a basic RPC configuration for testing."""
    return RPCConfigBase(
        full_nodes=[RPCNodeConfig(url=TEST_RPC_URL)],
        archive_nodes=[RPCNodeConfig(url=TEST_ARCHIVE_URL)],
        retry=3,
        request_time_out=10,
        connection_limits=ConnectionLimits(
            max_connections=100,
            max_keepalive_connections=50,
            keepalive_expiry=300
        )
    )


@pytest.fixture
def mock_web3() -> AsyncMock:
    """Fixture providing a mock Web3 instance."""
    mock = AsyncMock(spec=AsyncWeb3)
    
    # Mock eth module
    mock.eth = AsyncMock()
    # Create a property that returns a coroutine
    block_number_mock = AsyncMock(return_value=12345678)
    type(mock.eth).block_number = property(lambda _: block_number_mock())
    mock.eth.get_transaction = AsyncMock()
    mock.eth.get_transaction_receipt = AsyncMock()
    mock.eth.get_balance = AsyncMock()
    mock.eth.get_logs = AsyncMock()
    mock.eth.call = AsyncMock()
    
    # Mock contract creation
    mock.eth.contract = MagicMock()
    
    return mock


@pytest.fixture
def mock_contract() -> AsyncMock:
    """Fixture providing a mock contract instance."""
    mock = AsyncMock(spec=AsyncContract)
    mock.address = "0x1234567890123456789012345678901234567890"
    mock.abi = [
        {
            "name": "balanceOf",
            "type": "function",
            "inputs": [{"name": "account", "type": "address"}],
            "outputs": [{"name": "balance", "type": "uint256"}],
            "stateMutability": "view"
        },
        {
            "name": "totalSupply",
            "type": "function",
            "inputs": [],
            "outputs": [{"name": "supply", "type": "uint256"}],
            "stateMutability": "view"
        }
    ]
    return mock


@pytest.fixture
def mock_async_client() -> AsyncMock:
    """Fixture providing a mock HTTP client for testing external calls."""
    mock = AsyncMock(spec=httpx.AsyncClient)
    mock.post = AsyncMock()
    mock.get = AsyncMock()
    return mock


@pytest.fixture
def sample_transaction() -> Dict[str, Any]:
    """Fixture providing a sample transaction dictionary."""
    return {
        "hash": "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675",
        "blockHash": "0x1234567890abcdef",
        "blockNumber": 12345678,
        "from": "0x1234567890123456789012345678901234567890",
        "to": "0x0987654321098765432109876543210987654321",
        "value": 1000000000000000000,
        "gas": 21000,
        "gasPrice": 20000000000,
        "nonce": 1,
        "input": "0x",
        "transactionIndex": 0
    }


@pytest.fixture
def sample_transaction_receipt() -> Dict[str, Any]:
    """Fixture providing a sample transaction receipt."""
    return {
        "transactionHash": "0x16ff6b3fb198c54a36c76d689255aa06af2e701914ba42ec0533820c4c2c6675",
        "transactionIndex": 0,
        "blockHash": "0x1234567890abcdef",
        "blockNumber": 12345678,
        "from": "0x1234567890123456789012345678901234567890",
        "to": "0x0987654321098765432109876543210987654321",
        "cumulativeGasUsed": 21000,
        "gasUsed": 21000,
        "contractAddress": None,
        "logs": [],
        "status": "0x1",
        "logsBloom": "0x0"
    }


@pytest.fixture
def sample_event_logs() -> List[Dict[str, Any]]:
    """Fixture providing sample event logs."""
    return [
        {
            "address": "0x1234567890123456789012345678901234567890",
            "topics": [
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                "0x0000000000000000000000000000000000000000",
                "0x0000000000000000000000001234567890123456"
            ],
            "data": "0x0000000000000000000000000000000000000000000000000000000000000001",
            "blockNumber": 12345678,
            "transactionHash": "0xabcdef1234567890",
            "transactionIndex": 0,
            "blockHash": "0x1234567890abcdef",
            "logIndex": 0,
            "removed": False
        }
    ]


@pytest.fixture
def mock_abi() -> List[Dict[str, Any]]:
    """Fixture providing a sample ABI for testing."""
    return [
        {
            "constant": True,
            "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
            "type": "function"
        },
        {
            "constant": True,
            "inputs": [],
            "name": "totalSupply",
            "outputs": [{"name": "supply", "type": "uint256"}],
            "type": "function"
        },
        {
            "anonymous": False,
            "inputs": [
                {"indexed": True, "name": "from", "type": "address"},
                {"indexed": True, "name": "to", "type": "address"},
                {"indexed": False, "name": "value", "type": "uint256"}
            ],
            "name": "Transfer",
            "type": "event"
        }
    ]


@pytest.fixture
def rpc_helper_instance(rpc_config, mock_async_client):
    """Fixture providing an initialized RPC helper instance with mocked client."""
    helper = RpcHelper(rpc_config)
    
    # Mock the initialization to avoid actual network calls
    helper._client = mock_async_client
    helper._initialized = True
    helper._node_count = 1
    
    # Create mock web3 instance
    mock_w3_instance = AsyncMock()
    mock_w3_instance.eth = AsyncMock()
    # Create a property that returns a coroutine
    block_number_mock = AsyncMock(return_value=12345678)
    type(mock_w3_instance.eth).block_number = property(lambda _: block_number_mock())
    mock_w3_instance.eth.get_transaction = AsyncMock()
    mock_w3_instance.eth.get_transaction_receipt = AsyncMock()
    mock_w3_instance.eth.get_logs = AsyncMock()
    mock_w3_instance.eth.call = AsyncMock()
    
    # Initialize with mocked web3
    helper._nodes = [
        {
            'web3_client': mock_w3_instance,
            'rpc_url': TEST_RPC_URL
        }
    ]
    
    yield helper


@pytest.fixture
def mock_rate_limiter_response():
    """Fixture providing mock responses for rate limiter."""
    def _mock_response(allowed=True):
        mock_response = AsyncMock()
        mock_response.status_code = 200 if allowed else 429
        return mock_response
    return _mock_response


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
def disable_rate_limiter():
    """
    Automatically disable rate limiting for all tests.
    
    This fixture patches the check_rate_limit method of RpcHelper to always return True,
    effectively bypassing rate limiting during tests without modifying the actual code.
    """
    with patch('rpc_helper.rpc.RpcHelper.check_rate_limit', new_callable=AsyncMock) as mock_check:
        mock_check.return_value = True
        yield mock_check


@pytest.fixture
def sample_block_data():
    """Fixture providing sample block data."""
    return {
        "number": "0xbc614e",
        "hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "parentHash": "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
        "nonce": "0x1234567890abcdef",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "logsBloom": "0x0",
        "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "miner": "0x1234567890123456789012345678901234567890",
        "difficulty": "0x1234567890abcdef",
        "totalDifficulty": "0x1234567890abcdef",
        "extraData": "0x0",
        "size": "0x1234",
        "gasLimit": "0x7a1200",
        "gasUsed": "0x5208",
        "timestamp": "0x12345678",
        "transactions": [],
        "uncles": []
    }


@pytest.fixture
def mock_httpx_response():
    """Fixture providing mock HTTPX responses."""
    def _create_mock_response(status_code=200, json_data=None, text=None):
        mock_response = AsyncMock(spec=httpx.Response)
        mock_response.status_code = status_code
        mock_response.json = MagicMock(return_value=json_data or {})
        mock_response.text = text or ""
        return mock_response
    return _create_mock_response