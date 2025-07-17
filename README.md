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

## Logging

RPC Helper uses [Loguru](https://github.com/Delgan/loguru) for logging and provides flexible configuration options.

### Default Logging

By default, RPC Helper uses Loguru's standard console logging with module binding:

```python
from rpc_helper.rpc import RpcHelper

# Default logging - uses standard Loguru console output
rpc = RpcHelper(rpc_settings=rpc_config)
```

### Custom Logger

You can provide your own logger instance:

```python
from loguru import logger
from rpc_helper.rpc import RpcHelper

# Create a custom logger
custom_logger = logger.bind(service="MyService")
rpc = RpcHelper(rpc_settings=rpc_config, logger=custom_logger)
```

### Configuring File Logging

To enable file logging, use the configuration functions:

```python
from rpc_helper.utils.default_logger import configure_rpc_logging
from rpc_helper.utils.models.settings_model import LoggingConfig
from pathlib import Path

# Configure file logging
logging_config = LoggingConfig(
    enable_file_logging=True,
    log_dir=Path("logs/rpc_helper"),
    file_levels={
        "INFO": True,
        "WARNING": True,
        "ERROR": True,
        "CRITICAL": True
    },
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {module} | {message}",
    rotation="100 MB",
    retention="7 days",
    compression="zip"
)

# Apply the configuration (call this once, typically at application startup)
configure_rpc_logging(logging_config)

# Now create RPC Helper instances - they will use the configured logging
rpc = RpcHelper(rpc_settings=rpc_config)
```

### Debug Logging

Enable debug and trace logging for troubleshooting:

```python
from rpc_helper.utils.default_logger import enable_debug_logging

# Enable debug logging to console
debug_handler_id = enable_debug_logging()

# Create RPC Helper with debug mode
rpc = RpcHelper(rpc_settings=rpc_config, debug_mode=True)
```

### Working with External Logging Systems

RPC Helper's logging is designed to work alongside external logging configurations:

```python
# Your application's logging setup
from loguru import logger

# Remove default handler and configure your own
logger.remove()
logger.add("logs/app.log", rotation="1 day")
logger.add(sys.stderr, level="WARNING")

# RPC Helper will work with your logging setup
from rpc_helper.rpc import RpcHelper
rpc = RpcHelper(rpc_settings=rpc_config)

# Both your app logs and RPC Helper logs will work correctly
logger.info("Application started")
rpc._logger.info("RPC Helper initialized")
```

### Cleanup and Management

For advanced use cases, you can manage logging handlers:

```python
from rpc_helper.utils.default_logger import cleanup_rpc_logging, disable_rpc_file_logging

# Remove all RPC Helper file logging handlers
disable_rpc_file_logging()

# Clean up all RPC Helper logging configuration
cleanup_rpc_logging()
```

### Logging Configuration Options

The `LoggingConfig` class supports these options:

```python
from rpc_helper.utils.models.settings_model import LoggingConfig

config = LoggingConfig(
    # File logging
    enable_file_logging=True,  # Enable/disable file logging
    log_dir=Path("logs"),      # Directory for log files
    file_levels={              # Which levels to log to files
        "DEBUG": True,
        "INFO": True,
        "WARNING": True,
        "ERROR": True,
        "CRITICAL": True
    },
    
    # Console logging (optional - uses Loguru defaults if not specified)
    enable_console_logging=True,
    console_levels={
        "INFO": "stdout",      # Send INFO to stdout
        "WARNING": "stderr",   # Send WARNING+ to stderr
        "ERROR": "stderr",
        "CRITICAL": "stderr"
    },
    
    # Format and rotation
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {module} | {message}",
    rotation="100 MB",         # Rotate when files reach this size
    retention="7 days",        # Keep logs for this long
    compression="zip",         # Compress rotated logs
    module_name="RpcHelper"    # Module name for log binding
)
```
