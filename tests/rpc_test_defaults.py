"""
Default Ethereum mainnet RPC URLs for tests.

Override with TEST_RPC_URL (and optionally the same value for archive) when your
environment blocks public endpoints or you need a dedicated provider.
"""

import os

# LlamaRPC free tier often returns 403 from CI/datacenter IPs; publicnode is a stable default.
_DEFAULT_MAINNET_RPC = "https://ethereum.publicnode.com"

TEST_RPC_URL = os.getenv("TEST_RPC_URL", _DEFAULT_MAINNET_RPC)
TEST_ARCHIVE_URL = os.getenv("TEST_ARCHIVE_URL", TEST_RPC_URL)
