"""Adapter classes by tool name (docs/09_TOOL_CONTRACTS.md section 7)."""

from __future__ import annotations

from reconkit.adapters.assetfinder import AssetfinderAdapter
from reconkit.adapters.base import BaseToolAdapter, BinaryAdapter, HttpAdapter
from reconkit.adapters.certspotter import CertspotterAdapter
from reconkit.adapters.crtsh import CrtshAdapter
from reconkit.adapters.dnspython import DnsPythonAdapter
from reconkit.adapters.dnsx import DnsxAdapter
from reconkit.adapters.gau import GauAdapter
from reconkit.adapters.hackertarget import HackertargetAdapter
from reconkit.adapters.httpx_tool import HttpxAdapter
from reconkit.adapters.katana import KatanaAdapter
from reconkit.adapters.naabu import NaabuAdapter
from reconkit.adapters.otx import OtxAdapter
from reconkit.adapters.pyprobe import PyprobeAdapter
from reconkit.adapters.pyscan import PyscanAdapter
from reconkit.adapters.subfinder import SubfinderAdapter
from reconkit.adapters.tlsx import TlsxAdapter

ADAPTERS: dict[str, type[BaseToolAdapter]] = {
    "crtsh": CrtshAdapter,
    "certspotter": CertspotterAdapter,
    "otx": OtxAdapter,
    "hackertarget": HackertargetAdapter,
    "dnspython": DnsPythonAdapter,
    "pyprobe": PyprobeAdapter,
    "pyscan": PyscanAdapter,
    "subfinder": SubfinderAdapter,
    "assetfinder": AssetfinderAdapter,
    "httpx": HttpxAdapter,
    "naabu": NaabuAdapter,
    "dnsx": DnsxAdapter,
    "tlsx": TlsxAdapter,
    "katana": KatanaAdapter,
    "gau": GauAdapter,
}

__all__ = ["ADAPTERS", "BaseToolAdapter", "BinaryAdapter", "HttpAdapter"]
