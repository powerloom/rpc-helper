"""
Unit tests for RPCHelper initialization and basic configuration.

These tests focus on verifying that the RPCHelper class initializes correctly
with various configuration scenarios, ensuring proper node selection and
initialization behavior.
"""
import pytest
from unittest.mock import patch, AsyncMock

from rpc_helper.rpc import RpcHelper
from rpc_helper.utils.models.settings_model import RPCConfigBase, RPCNodeConfig, ConnectionLimits


class TestRpcHelperInitialization:
    """Test cases for RPCHelper initialization."""

    @pytest.mark.unit
    def test_initialization_with_full_nodes(self, rpc_config):
        """Test that RPCHelper initializes correctly with full nodes."""
        helper = RpcHelper(rpc_config)
        
        assert helper._rpc_settings == rpc_config
        assert helper._archive_mode is False
        assert helper._node_count == 0  # Not initialized yet
        assert helper._current_node_index == 0
        assert helper._initialized is False

    @pytest.mark.unit
    def test_initialization_with_archive_mode(self, rpc_config):
        """Test that RPCHelper initializes correctly with archive mode enabled."""
        helper = RpcHelper(rpc_config, archive_mode=True)
        
        assert helper._archive_mode is True
        assert helper._rpc_settings == rpc_config

    @pytest.mark.unit
    def test_initialization_with_debug_mode(self, rpc_config):
        """Test that RPCHelper initializes correctly with debug mode enabled."""
        helper = RpcHelper(rpc_config, debug_mode=True)
        
        assert helper._debug_mode is True
        assert helper._logger is not None

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_init_loads_providers(self, rpc_config):
        """Test that init() properly loads web3 providers."""
        helper = RpcHelper(rpc_config)
        
        # Mock the async web3 initialization
        with patch('rpc_helper.rpc.AsyncWeb3') as mock_w3:
            mock_instance = AsyncMock()
            mock_w3.return_value = mock_instance
            
            await helper.init()
            
            assert helper._initialized is True
            assert helper._node_count == 1
            assert len(helper._nodes) == 1
            assert helper._nodes[0]['rpc_url'] == rpc_config.full_nodes[0].url

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_init_with_archive_nodes(self, rpc_config):
        """Test that init() uses archive nodes when archive mode is enabled."""
        helper = RpcHelper(rpc_config, archive_mode=True)
        
        with patch('rpc_helper.rpc.AsyncWeb3') as mock_w3:
            mock_instance = AsyncMock()
            mock_w3.return_value = mock_instance
            
            await helper.init()
            
            assert helper._node_count == 1
            assert helper._nodes[0]['rpc_url'] == rpc_config.archive_nodes[0].url

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_init_only_initializes_once(self, rpc_config):
        """Test that init() only initializes once."""
        helper = RpcHelper(rpc_config)
        
        with patch('rpc_helper.rpc.AsyncWeb3') as mock_w3:
            mock_instance = AsyncMock()
            mock_w3.return_value = mock_instance
            
            # First call
            await helper.init()
            original_node_count = helper._node_count
            
            # Second call should not change anything
            await helper.init()
            assert helper._node_count == original_node_count

    @pytest.mark.unit
    def test_get_current_node_with_no_nodes(self, rpc_config):
        """Test that get_current_node raises exception when no nodes are available."""
        helper = RpcHelper(rpc_config)
        
        with pytest.raises(Exception, match="No full nodes available"):
            helper.get_current_node()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_get_current_node_returns_node(self, rpc_helper_instance):
        """Test that get_current_node returns the current node after initialization."""
        node = rpc_helper_instance.get_current_node()
        
        assert node is not None
        assert 'web3_client' in node
        assert 'rpc_url' in node
        assert node['rpc_url'] == "https://eth.llamarpc.com"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_init_http_clients(self, rpc_config):
        """Test that HTTP clients are initialized correctly."""
        helper = RpcHelper(rpc_config)
        
        await helper._init_http_clients()
        
        assert helper._client is not None
        assert helper._async_transport is not None

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_init_http_clients_only_once(self, rpc_config):
        """Test that HTTP clients are only initialized once."""
        helper = RpcHelper(rpc_config)
        
        await helper._init_http_clients()
        original_client = helper._client
        
        await helper._init_http_clients()
        assert helper._client is original_client