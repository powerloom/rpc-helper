# RPC Helper Test Suite

A comprehensive test suite for the RPC Helper.

## Test Structure

```
tests/
├── unit/                    # Unit tests for individual components
│   ├── test_rpc_initialization.py    # RPCHelper initialization tests
│   ├── test_rpc_transactions.py      # Transaction operation tests
│   ├── test_rpc_blocks.py           # Block operation tests
│   ├── test_rpc_contract_calls.py   # Contract call tests
│   ├── test_rpc_events.py           # Event log tests
│   ├── test_rpc_balance_operations.py # Balance operation tests
│   └── test_rpc_edge_cases.py       # Edge cases and error handling
├── integration/             # Integration tests with real RPC endpoints
│   └── test_rpc_integration.py      # Real-world RPC interactions
├── fixtures/                # Shared test fixtures and mock objects
└── conftest.py             # Pytest configuration and fixtures
```

## Quick Start

### Run All Tests
```bash
pytest
```

### Run Only Unit Tests
```bash
python run_tests.py --unit
# or
pytest -m unit
```

### Run Only Integration Tests (requires network)
```bash
python run_tests.py --integration
# or
pytest -m integration
```

### Run with Coverage
```bash
python run_tests.py --coverage
# or
pytest --cov=rpc_helper --cov-report=html
```

## Test Categories

### Unit Tests (`-m unit`)
- **Initialization**: RPCHelper setup, configuration, and initialization
- **Transactions**: Transaction retrieval, receipts, and validation
- **Blocks**: Block number retrieval and block data access
- **Contract Calls**: Web3 contract interactions and batch operations
- **Events**: Event log retrieval and filtering
- **Balances**: Ethereum balance operations across block ranges
- **Edge Cases**: Error handling, invalid inputs, and boundary conditions

### Integration Tests (`-m integration`)
- **Real RPC Interactions**: Tests against actual Ethereum endpoints
- **Network Connectivity**: Endpoint availability verification
- **Multi-node Fallback**: Automatic node rotation on failures
- **Real Data Validation**: Transaction and block data from mainnet

## Configuration

### Environment Variables
- `TEST_RPC_URL`: RPC endpoint for integration tests (default: https://eth.llamarpc.com)

### Test Configuration
- **Timeout**: 30 seconds for integration tests
- **Retries**: 2-3 attempts for network operations
- **Concurrent**: Supports parallel test execution

## Test Markers

| Marker | Description |
|--------|-------------|
| `unit` | Unit tests (fast, no network) |
| `integration` | Integration tests (requires network) |
| `network` | Tests requiring network access |
| `slow` | Slow-running tests |

## Running Specific Tests

```bash
# Specific test file
pytest tests/unit/test_rpc_transactions.py

# Specific test function
pytest tests/unit/test_rpc_transactions.py::test_get_transaction_from_hash_success

# Tests matching pattern
pytest -k "balance"

# Verbose output
pytest -v
```

## Coverage

Generate coverage reports:
```bash
pytest --cov=rpc_helper --cov-report=html
open htmlcov/index.html
```

## Troubleshooting

### Integration Tests Failing
- Check `TEST_RPC_URL` environment variable
- Verify network connectivity
- Check RPC endpoint rate limits

### Import Errors
- Ensure all dependencies are installed: `poetry install`
- Check Python path includes the project root

### Async Issues
- Use `pytest-asyncio` with `asyncio_mode = auto` in pytest.ini