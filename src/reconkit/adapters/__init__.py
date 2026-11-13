"""Adapter classes by tool name (docs/09_TOOL_CONTRACTS.md section 7)."""

from __future__ import annotations

from reconkit.adapters.base import BaseToolAdapter, HttpAdapter
from reconkit.adapters.certspotter import CertspotterAdapter
from reconkit.adapters.crtsh import CrtshAdapter
from reconkit.adapters.dnspython import DnsPythonAdapter
from reconkit.adapters.hackertarget import HackertargetAdapter
from reconkit.adapters.otx import OtxAdapter
from reconkit.adapters.pyprobe import PyprobeAdapter
from reconkit.adapters.pyscan import PyscanAdapter

ADAPTERS: dict[str, type[BaseToolAdapter]] = {
    "crtsh": CrtshAdapter,
    "certspotter": CertspotterAdapter,
    "otx": OtxAdapter,
    "hackertarget": HackertargetAdapter,
    "dnspython": DnsPythonAdapter,
    "pyprobe": PyprobeAdapter,
    "pyscan": PyscanAdapter,
}

__all__ = ["ADAPTERS", "BaseToolAdapter", "HttpAdapter"]
