# RPC-Helper

An asynchronous Python helper library for interacting with Ethereum RPC nodes, featuring retry logic and multi-node support.

## Features

- **Multi-Node Support**: Automatically distributes requests across multiple Ethereum RPC nodes
- **Automatic Failover**: Intelligent retry logic with exponential backoff
- **Archive Mode**: Support for both regular and archive nodes
- **Rate Limiting**: Built-in rate limiting to prevent overwhelming nodes
- **Async/Await**: Fully asynchronous API for non-blocking operations
- **Batch Operations**: Efficient batched RPC calls for better performance
- **Advanced Logging**: Comprehensive logging with multiple levels
- **Web3.py Integration**: Seamless integration with web3.py

## Quick Start

```python
import asyncio
from rpc_helper.utils.models.settings_model import RPCConfigBase, RPCNodeConfig, ConnectionLimits
from rpc_helper.rpc import RpcHelper

async def main():
    # Create RPC configuration
    rpc_config = RPCConfigBase(
        full_nodes=[
            RPCNodeConfig(url="https://eth-mainnet.provider1.io"),
            RPCNodeConfig(url="https://eth-mainnet.provider2.io")
        ],
        archive_nodes=[
            RPCNodeConfig(url="https://eth-mainnet-archive.provider.io")
        ],
        force_archive_blocks=10000,  # Use archive nodes for blocks older than this
        retry=3,  # Number of retries before giving up
        request_time_out=15,  # Seconds
        connection_limits=ConnectionLimits(
            max_connections=100,
            max_keepalive_connections=50,
            keepalive_expiry=300
        )
    )
    
    # Initialize RPC helper
    rpc = RpcHelper(rpc_settings=rpc_config)
    await rpc.init()
    
    # Get current block number
    block_number = await rpc.get_current_block_number()
    print(f"Current block number: {block_number}")
    
    # Get transaction details
    tx_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    tx_details = await rpc.get_transaction_from_hash(tx_hash)
    print(f"Transaction details: {tx_details}")

asyncio.run(main())
```

## Advanced Usage

### Working with Smart Contracts

```python
from web3 import Web3
from web3.contract import AsyncContract

async def contract_example():
    # Initialize RPC helper (as shown in Quick Start)
    
    # ERC-20 contract ABI (simplified for example)
    abi = [
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
            "name": "symbol",
            "outputs": [{"name": "", "type": "string"}],
            "type": "function"
        }
    ]
    
    # Contract address (USDT on Ethereum)
    contract_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    
    # Create tasks for batch call
    tasks = [
        ("symbol", []),  # Get token symbol
        ("balanceOf", [Web3.to_checksum_address("0x1234567890123456789012345678901234567890")])  # Get balance
    ]
    
    # Make batch call
    results = await rpc.web3_call(tasks, contract_address, abi)
    symbol, balance = results
    
    print(f"Token: {symbol}")
    print(f"Balance: {balance}")
```

### Batch Processing Blocks

```python
async def batch_processing_example():
    # Initialize RPC helper (as shown in Quick Start)
    
    # Process a range of blocks
    start_block = 15000000
    end_block = 15000010
    
    # Get blocks in batch
    blocks = await rpc.batch_eth_get_block(start_block, end_block)
    
    for block in blocks:
        print(f"Block {block['number']}: {len(block['transactions'])} transactions")
```

### Event Log Processing

```python
async def event_logs_example():
    # Initialize RPC helper (as shown in Quick Start)
    
    # Contract address and event details
    contract_address = "0x1234567890123456789012345678901234567890"
    
    # Event ABI
    event_abi = {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "name": "from", "type": "address"},
            {"indexed": True, "name": "to", "type": "address"},
            {"indexed": False, "name": "value", "type": "uint256"}
        ],
        "name": "Transfer",
        "type": "event"
    }
    
    # Event signature
    event_signatures = {
        "Transfer": "Transfer(address,address,uint256)"
    }
    
    # Get event signatures and ABIs
    from rpc_helper.rpc import get_event_sig_and_abi
    event_sig, event_abi_dict = get_event_sig_and_abi(event_signatures, {"Transfer": event_abi})
    
    # Get logs for a block range
    from_block = 15000000
    to_block = 15000100
    
    logs = await rpc.get_events_logs(
        contract_address=contract_address,
        from_block=from_block,
        to_block=to_block,
        topics=[event_sig],  # Filter by event signature
        event_abi=event_abi_dict
    )
    
    for log in logs:
        print(f"Transfer: {log['args']['from']} -> {log['args']['to']}, Value: {log['args']['value']}")
```

## Error Handling

The library uses a custom `RPCException` class to provide detailed error information:

```python
try:
    # Make RPC call
    result = await rpc.get_transaction_from_hash(tx_hash)
except RPCException as e:
    print(f"RPC Error: {e}")
    print(f"Request: {e.request}")
    print(f"Response: {e.response}")
    print(f"Underlying Exception: {e.underlying_exception}")
    print(f"Extra Info: {e.extra_info}")
```

## Debugging

Enable debug mode for detailed logging:

```python
# Enable debug mode
rpc = RpcHelper(rpc_settings=rpc_config, debug_mode=True)
```

## Development

### Setup

1. Clone the repository:
```bash
git clone https://github.com/powerloom/rpc-helper.git
cd rpc-helper
```

2. Install dependencies using Poetry:
```bash
poetry install
```

3. Install pre-commit hooks:
```bash
poetry run pre-commit install
```

### Code Quality

This project maintains high code quality standards using automated tools:

#### Tools Used
- **black** (v25.1.0) - Code formatting
- **isort** (v6.0.1) - Import sorting  
- **flake8** (v7.3.0) - Linting
- **pre-commit** (v4.2.0) - Git hooks

#### Quick Quality Check

```bash
# Check code quality without making changes
./scripts/verify_code_quality.sh

# Auto-fix formatting issues
./scripts/verify_code_quality.sh --fix
```

#### Manual Commands

```bash
# Check formatting
poetry run black --check rpc_helper/ tests/
poetry run isort --check-only rpc_helper/ tests/
poetry run flake8 .

# Apply formatting
poetry run black rpc_helper/ tests/
poetry run isort rpc_helper/ tests/
```

### Pre-commit Hooks

Pre-commit hooks automatically verify code quality before each commit:

```bash
# Install hooks (one-time setup)
poetry run pre-commit install

# Run manually on all files
poetry run pre-commit run --all-files
```

**Checks performed:**
- Python syntax validation
- Code formatting (black)
- Import sorting (isort)
- Linting (flake8)
- Large file detection
- YAML/JSON/TOML validation
- Merge conflict detection

> **Note**: Pre-commit hooks do not automatically modify files. If issues are detected, the commit will be blocked and you'll need to fix them manually or run `./scripts/verify_code_quality.sh --fix`.

### Testing

Run the test suite using pytest:

```bash
# Run all tests
poetry run pytest

# Run unit tests only
poetry run pytest tests/unit/

# Run integration tests only
poetry run pytest tests/integration/

# Run with coverage
poetry run pytest --cov=rpc_helper --cov-report=term-missing

# Run specific test markers
poetry run pytest -m unit
poetry run pytest -m integration
poetry run pytest -m "not slow"
```

### CI/CD Pipeline

GitHub Actions automatically runs on every push and pull request:

1. **Linting** - Validates code formatting and style
2. **Testing** - Runs test suite on Python 3.10, 3.11, and 3.12
3. **Coverage** - Generates and uploads coverage reports
4. **Building** - Builds distribution packages

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run quality checks (`./scripts/verify_code_quality.sh`)
5. Run tests (`poetry run pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

#### Development Best Practices

- Write tests for new features
- Maintain or improve code coverage
- Follow existing code patterns and conventions
- Update documentation as needed
- Ensure all quality checks pass before submitting PR
