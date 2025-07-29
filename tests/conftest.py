"""
Pytest configuration and shared fixtures for the RPC Helper test suite.
This module provides common test fixtures, mock objects, and configuration
used across the test suite.
"""
import asyncio
from typing import Dict, List, Any
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from hexbytes import HexBytes

import pytest
import httpx
from web3 import AsyncWeb3
from web3 import Web3

from rpc_helper.rpc import RpcHelper
from rpc_helper.utils.models.settings_model import RPCConfigBase, RPCNodeConfig, ConnectionLimits


# Test configuration
TEST_RPC_URL = "https://eth.llamarpc.com"
TEST_ARCHIVE_URL = "https://eth.llamarpc.com"

# Global state for contract function return values
_global_function_return_values = {}


class AwaitableProperty:
    """A property that can be awaited and returns a fresh coroutine each time."""
    def __init__(self, value):
        self.value = value
        
    def __await__(self):
        async def coro():
            return self.value
        return coro().__await__()
    

class FailingAwaitableProperty:
    """A property that can be awaited and raises an error each time."""
    def __init__(self, error):
        self.error = error
        
    def __await__(self):
        async def coro():
            raise self.error
        return coro().__await__()


class ContractFunctionsMock:
    """Mock class that handles both dictionary and attribute access for contract functions."""
    def __init__(self):
        self._function_mocks = {}
    
    def _get_function_mock(self, name: str):
        """Get or create a function mock for the given name."""
        if name not in self._function_mocks:
            # Create async mock that returns the configured value from global state
            async_call = AsyncMock(return_value=_global_function_return_values.get(name, 1000))
            
            # Create function mock that has both call() and _encode_transaction_data()
            function_mock = Mock()
            function_mock.call = async_call
            function_mock._encode_transaction_data = Mock(return_value=f"0x{name[:8]}...")
            
            # Create factory that returns the function mock when called with args
            factory = Mock(return_value=function_mock)
            
            self._function_mocks[name] = factory
        
        return self._function_mocks[name]
    
    def __getitem__(self, key):
        """Handle dictionary-style access: functions["balanceOf"]."""
        return self._get_function_mock(key)
    
    def __getattr__(self, name):
        """Handle attribute-style access: functions.balanceOf."""
        return self._get_function_mock(name)
    
    def set_return_value(self, function_name: str, value: Any):
        """Set the return value for a specific function globally."""
        _global_function_return_values[function_name] = value
        # Update existing mocks across all instances
        if function_name in self._function_mocks:
            factory = self._function_mocks[function_name]
            function_mock = factory.return_value
            function_mock.call.return_value = value


class LogMock:
    """Mock log object that behaves like Web3's AttributeDict."""
    
    def __init__(self, address=None, topics=None, data=None, block_number=None, 
                 tx_hash=None, tx_index=0, block_hash=None, log_index=0, removed=False):
        self.address = address or "0x1234567890123456789012345678901234567890"
        self.topics = topics or [
            HexBytes("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"),
            HexBytes("0x0000000000000000000000000000000000000000"),
            HexBytes("0x0000000000000000000000001234567890123456")
        ]
        self.data = data or HexBytes("0x0000000000000000000000000000000000000000000000000000000000000001")
        self.blockNumber = block_number or 12345678
        self.transactionHash = HexBytes(tx_hash or "0xabcdef1234567890")
        self.transactionIndex = tx_index
        self.blockHash = HexBytes(block_hash or "0x1234567890abcdef")
        self.logIndex = log_index
        self.removed = removed
        
    def __getitem__(self, key):
        """Support dictionary-style access."""
        return getattr(self, key)
        
    def __setitem__(self, key, value):
        """Support dictionary-style assignment."""
        setattr(self, key, value)
        
    def __contains__(self, key):
        """Support 'in' operator."""
        return hasattr(self, key)
        
    def get(self, key, default=None):
        """Support dict.get() method."""
        return getattr(self, key, default)


@pytest.fixture(autouse=True)
def clear_global_state():
    """Clear global state before each test."""
    global _global_function_return_values
    _global_function_return_values.clear()
    yield
    _global_function_return_values.clear()


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
    """Fixture providing a mock Web3 instance with proper contract support."""
    mock = AsyncMock(spec=AsyncWeb3)
    
    # Mock eth module
    mock.eth = AsyncMock()
    
    # Use AwaitableProperty for block_number to support concurrent access
    mock.eth.block_number = AwaitableProperty(12345678)
    mock.to_checksum_address = Web3.to_checksum_address
    
    # Mock standard eth methods
    mock.eth.get_transaction = AsyncMock()
    mock.eth.get_transaction_receipt = AsyncMock()
    mock.eth.get_balance = AsyncMock()
    mock.eth.get_logs = AsyncMock()
    mock.eth.call = AsyncMock()
    
    # Mock codec (required for event decoding)
    mock.codec = AsyncMock()
    
    # Contract creation that returns properly structured contracts
    def create_contract(*args, **kwargs):
        contract_mock = Mock()
        contract_mock.functions = ContractFunctionsMock()
        contract_mock.abi = kwargs.get('abi', [])
        contract_mock.address = kwargs.get('address', '0x0')
        return contract_mock
    
    mock.eth.contract = Mock(side_effect=create_contract)
    
    return mock


@pytest.fixture
def mock_contract() -> Mock:
    """Fixture providing a simple mock contract instance."""
    mock = Mock()
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
    
    # Use our ContractFunctionsMock
    mock.functions = ContractFunctionsMock()
    
    return mock


@pytest.fixture
def mock_async_client() -> AsyncMock:
    """Fixture providing a simple mock HTTP client."""
    mock = AsyncMock(spec=httpx.AsyncClient)
    
    class MockResponse:
        def __init__(self):
            self.status_code = 200
            self._json_data = []
            self.text = ""
        
        def json(self):
            """Return json data to match httpx behavior."""
            return self._json_data
        
        def set_json_data(self, data):
            self._json_data = data
    
    mock_response = MockResponse()
    
    mock.post = AsyncMock(return_value=mock_response)
    mock.get = AsyncMock(return_value=mock_response)
    
    return mock


@pytest.fixture
def rpc_helper_instance(rpc_config, mock_async_client, mock_web3):
    """Fixture providing an initialized RPC helper instance with mocked client."""
    helper = RpcHelper(rpc_config)
    
    # Simple initialization
    helper._client = mock_async_client
    helper._initialized = True
    helper._node_count = 1
    
    # Use the shared mock_web3 fixture
    helper._nodes = [
        {
            'web3_client': mock_web3,
            'rpc_url': TEST_RPC_URL
        }
    ]
    
    yield helper


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
    
    # Create a mock log object that behaves like Web3's AttributeDict
    # It needs to support both attribute access (log.topics) and dict access (log["topics"])
    log_mock = LogMock()
    return [log_mock]


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