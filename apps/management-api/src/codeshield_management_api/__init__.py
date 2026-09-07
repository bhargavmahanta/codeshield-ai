"""CodeShield metadata-only management API."""

from codeshield_management_api.app import create_app
from codeshield_management_api.config import ManagementSettings

__all__ = ["ManagementSettings", "create_app"]
