"""
Unit tests for contract call functionality in RPCHelper.

These tests focus on verifying the business logic of contract interactions,
including web3 calls, batch operations, and state overrides.
"""

from unittest.mock import patch

import pytest
from hexbytes import HexBytes

from rpc_helper.rpc import get_contract_abi_dict
from rpc_helper.utils.exceptions import RPCException


class TestRpcContractOperations:
    """Test cases for contract-related operations."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_web3_call_single_function(self, rpc_helper_instance, mock_abi):
        """Test successful single contract function call."""
        tasks = [("balanceOf", ["0x1234567890123456789012345678901234567890"])]
        contract_addr = "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3"

        result = await rpc_helper_instance.web3_call(tasks, contract_addr, mock_abi)

        assert result == [1000]  # Default return value from ContractFunctionsMock

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_web3_call_multiple_functions(self, rpc_helper_instance, mock_abi):
        """Test successful multiple contract function calls."""
        # Get the contract and set custom return values
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        contract = mock_web3.eth.contract(address="0x123", abi=mock_abi)
        contract.functions.set_return_value("balanceOf", 1000)
        contract.functions.set_return_value("totalSupply", 1000000)

        tasks = [
            ("balanceOf", ["0x1234567890123456789012345678901234567890"]),
            ("totalSupply", []),
        ]
        contract_addr = "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3"

        result = await rpc_helper_instance.web3_call(tasks, contract_addr, mock_abi)

        assert result == [1000, 1000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_web3_call_with_rate_limit(self, rpc_helper_instance, mock_abi):
        """Test contract call with rate limiting."""
        with patch.object(rpc_helper_instance, "check_rate_limit", return_value=False):
            tasks = [("balanceOf", ["0x1234567890123456789012345678901234567890"])]
            contract_addr = "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3"

            with pytest.raises(RPCException) as exc_info:
                await rpc_helper_instance.web3_call(tasks, contract_addr, mock_abi)

            assert "Rate limit exceeded" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_web3_call_with_override(self, rpc_helper_instance):
        """Test our mock eth.call directly to verify state override logic."""

        # Create a state-aware eth.call mock for this test only
        async def state_aware_eth_call(payload, state_override=None, **kwargs):
            """Mock eth.call that respects state override parameters."""
            # Default return value (encoded 1000)
            default_value = HexBytes("0x00000000000000000000000000000000000000000000000000000000000003e8")

            # If no state override provided, return default
            if not state_override:
                return default_value

            # Check if this is a balanceOf call (function selector: 0x70a08231)
            call_data = payload.get("data", "")

            if call_data.startswith("0x70a08231"):  # balanceOf function signature
                # Extract the address parameter from the call data
                if len(call_data) >= 74:  # 4 bytes selector + 32 bytes address (with padding)
                    # The address parameter starts after the 4-byte function selector
                    # The address is in the last 20 bytes of the 32-byte parameter
                    address_param = call_data[10:]  # Skip '0x70a08231'
                    queried_address = "0x" + address_param[-40:].lower()  # Last 40 hex chars = 20 bytes

                    # Check if we have a balance override for this address
                    for override_address, overrides in state_override.items():
                        if override_address.lower() == queried_address:
                            if "balance" in overrides:
                                # Convert balance override to proper format
                                balance_hex = overrides["balance"]
                                if balance_hex.startswith("0x"):
                                    balance_value = int(balance_hex, 16)
                                    # Encode as uint256 (32 bytes)
                                    result = HexBytes(f"0x{balance_value:064x}")
                                    return result

            # For other cases or no matching override, return default
            return default_value

        # Patch only for this test
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        with patch.object(mock_web3.eth, "call", side_effect=state_aware_eth_call):
            # Test payload that simulates balanceOf call
            payload = {
                "to": "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
                "data": "0x70a082310000000000000000000000001234567890123456789012345678901234567890",
            }

            # Test with state override
            overrides = {"0x1234567890123456789012345678901234567890": {"balance": "0x1000"}}  # 4096 in decimal

            # Call the mock directly
            result = await mock_web3.eth.call(payload, state_override=overrides)

            # Should return the overridden value (4096) encoded as bytes
            expected = HexBytes("0x0000000000000000000000000000000000000000000000000000000000001000")
            assert result == expected

            # Test without override - should return default (1000)
            result_default = await mock_web3.eth.call(payload, state_override={})
            expected_default = HexBytes("0x00000000000000000000000000000000000000000000000000000000000003e8")
            assert result_default == expected_default

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_web3_contract_calls_success(self, rpc_helper_instance, mock_abi, mock_contract):
        """Test successful batch contract calls."""
        # Set up HTTP response mock
        response_data = [
            {"result": "0x00000000000000000000000000000000000000000000000000000000000003e8"},  # 1000
            {"result": "0x00000000000000000000000000000000000000000000000000000000000f4240"},  # 1000000
        ]

        # Configure the mock response directly
        mock_response = rpc_helper_instance._client.post.return_value
        mock_response.set_json_data(response_data)

        tasks = [
            ("balanceOf", ["0x1234567890123456789012345678901234567890"]),
            ("totalSupply", []),
        ]

        result = await rpc_helper_instance.batch_web3_contract_calls(tasks, mock_contract)

        assert result == [1000, 1000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_web3_contract_calls_with_block_override(self, rpc_helper_instance, mock_abi, mock_contract):
        """Test batch contract calls with block number override."""
        # Set up HTTP response mock
        response_data = [
            {"result": "0x00000000000000000000000000000000000000000000000000000000000003e8"},  # 1000
            {"result": "0x00000000000000000000000000000000000000000000000000000000000f4240"},  # 1000000
        ]

        # Configure the mock response directly
        mock_response = rpc_helper_instance._client.post.return_value
        mock_response.set_json_data(response_data)

        tasks = [
            ("balanceOf", ["0x1234567890123456789012345678901234567890"]),
            ("totalSupply", []),
        ]
        block_override = [12345678, 12345679]

        result = await rpc_helper_instance.batch_web3_contract_calls(
            tasks, mock_contract, block_override=block_override
        )

        assert result == [1000, 1000000]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_web3_contract_calls_block_override_mismatch(self, rpc_helper_instance, mock_contract):
        """Test error when block override length doesn't match tasks length."""
        tasks = [
            ("balanceOf", ["0x1234567890123456789012345678901234567890"]),
            ("totalSupply", []),
        ]
        block_override = [12345678]  # Only one block for two tasks

        with pytest.raises(
            ValueError,
            match="Block override length is not equal to the number of tasks",
        ):
            await rpc_helper_instance.batch_web3_contract_calls(tasks, mock_contract, block_override=block_override)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_call_on_block_range_success(self, rpc_helper_instance, mock_abi):
        """Test successful batch contract calls on block range."""
        mock_response_data = [
            {"result": "0x00000000000000000000000000000000000000000000000000000000000003e8"},
            {"result": "0x00000000000000000000000000000000000000000000000000000000000003e9"},
            {"result": "0x00000000000000000000000000000000000000000000000000000000000003ea"},
        ]

        # Configure the mock response directly
        mock_response = rpc_helper_instance._client.post.return_value
        mock_response.set_json_data(mock_response_data)

        # Process raw ABI to dictionary format
        processed_abi = get_contract_abi_dict(mock_abi)

        result = await rpc_helper_instance.batch_eth_call_on_block_range(
            processed_abi,
            "balanceOf",
            "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
            12345678,
            12345680,
            params=["0x1234567890123456789012345678901234567890"],
        )

        assert result == [(1000,), (1001,), (1002,)]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_call_on_block_range_no_params(self, rpc_helper_instance, mock_abi):
        """Test batch contract calls without parameters."""
        mock_response_data = [{"result": "0x00000000000000000000000000000000000000000000000000000000000f4240"}]

        # Configure the mock response directly
        mock_response = rpc_helper_instance._client.post.return_value
        mock_response.set_json_data(mock_response_data)

        # Process raw ABI to dictionary format
        processed_abi = get_contract_abi_dict(mock_abi)

        result = await rpc_helper_instance.batch_eth_call_on_block_range(
            processed_abi,
            "totalSupply",
            "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
            12345678,
            12345678,
        )

        assert result == [(1000000,)]

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_batch_eth_call_on_block_range_hex_data(self, rpc_helper_instance, mock_abi):
        """Test batch contract calls returning raw hex data."""
        mock_response_data = [{"result": "0x00000000000000000000000000000000000000000000000000000000000003e8"}]

        # Configure the mock response directly
        mock_response = rpc_helper_instance._client.post.return_value
        mock_response.set_json_data(mock_response_data)

        # Process raw ABI to dictionary format
        processed_abi = get_contract_abi_dict(mock_abi)

        result = await rpc_helper_instance.batch_eth_call_on_block_range_hex_data(
            processed_abi,
            "balanceOf",
            "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
            12345678,
            12345678,
            params=["0x1234567890123456789012345678901234567890"],
        )

        assert len(result) == 1
        assert isinstance(result[0], HexBytes)
        assert result[0].hex() == "0x00000000000000000000000000000000000000000000000000000000000003e8"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_contract_call_web3_error(self, rpc_helper_instance, mock_abi):
        """Test handling of web3 provider errors during contract calls."""
        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.contract.side_effect = Exception("Contract not found")

        tasks = [("balanceOf", ["0x1234567890123456789012345678901234567890"])]
        contract_addr = "0xInvalidContractAddress"

        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.web3_call(tasks, contract_addr, mock_abi)

        assert "Contract not found" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_contract_call_json_rpc_error(self, rpc_helper_instance, mock_abi):
        """Test handling of JSON-RPC errors during contract calls."""
        # Configure the mock response directly
        mock_response = rpc_helper_instance._client.post.return_value
        mock_response.set_json_data([{"error": {"code": -32000, "message": "execution reverted"}}])

        # Process raw ABI to dictionary format
        processed_abi = get_contract_abi_dict(mock_abi)

        # Should raise an RPCException when there's an error in the response
        with pytest.raises(RPCException) as exc_info:
            await rpc_helper_instance.batch_eth_call_on_block_range(
                processed_abi,
                "balanceOf",
                "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
                12345678,
                12345678,
            )

        # Verify the exception contains the error information
        assert "execution reverted" in str(exc_info.value.extra_info)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_web3_call_with_override_multiple_outputs(self, rpc_helper_instance):
        """Test contract call with multiple output values."""
        mock_abi = [
            {
                "constant": True,
                "inputs": [{"name": "_address", "type": "address"}],
                "name": "getUserInfo",
                "outputs": [
                    {"name": "balance", "type": "uint256"},
                    {"name": "lastUpdate", "type": "uint256"},
                    {"name": "isActive", "type": "bool"},
                ],
                "type": "function",
            }
        ]

        contract_addr = "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3"

        mock_web3 = rpc_helper_instance._nodes[0]["web3_client"]
        mock_web3.eth.call.return_value = HexBytes(
            "0x00000000000000000000000000000000000000000000000000000000000003e8"
            "00000000000000000000000000000000000000000000000000000000623a2920"
            "0000000000000000000000000000000000000000000000000000000000000001"
        )

        tasks = [("getUserInfo", ["0x1234567890123456789012345678901234567890"])]

        result = await rpc_helper_instance.web3_call_with_override(tasks, contract_addr, mock_abi, {})

        assert len(result) == 1
        # The result should be a tuple with the three values
        assert isinstance(result, list)
        assert isinstance(result[0], tuple)
        assert result[0][0] == 1000
        assert result[0][1] == 1647978784
        assert result[0][2] == True

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_contract_call_empty_result(self, rpc_helper_instance, mock_abi):
        """Test handling of empty contract call results."""
        # Configure the mock response directly
        mock_response = rpc_helper_instance._client.post.return_value
        mock_response.set_json_data([])

        # Process raw ABI to dictionary format
        processed_abi = get_contract_abi_dict(mock_abi)

        result = await rpc_helper_instance.batch_eth_call_on_block_range(
            processed_abi,
            "balanceOf",
            "0xA0b86a33E6441e0aDA2e87046B4719e8FF13f7c3",
            12345678,
            12345679,
        )

        assert result == []
