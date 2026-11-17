"""Adapter classes by tool name (docs/09_TOOL_CONTRACTS.md section 7)."""

from __future__ import annotations

from reconkit.adapters.amass import AmassAdapter
from reconkit.adapters.assetfinder import AssetfinderAdapter
from reconkit.adapters.base import BaseToolAdapter, BinaryAdapter, HttpAdapter
from reconkit.adapters.cdncheck import CdncheckAdapter
from reconkit.adapters.certspotter import CertspotterAdapter
from reconkit.adapters.chaos import ChaosAdapter
from reconkit.adapters.crtsh import CrtshAdapter
from reconkit.adapters.dnspython import DnsPythonAdapter
from reconkit.adapters.dnsx import DnsxAdapter
from reconkit.adapters.ffuf import FfufAdapter
from reconkit.adapters.findomain import FindomainAdapter
from reconkit.adapters.gau import GauAdapter
from reconkit.adapters.github_subdomains import GithubSubdomainsAdapter
from reconkit.adapters.gospider import GospiderAdapter
from reconkit.adapters.hackertarget import HackertargetAdapter
from reconkit.adapters.hakrawler import HakrawlerAdapter
from reconkit.adapters.httprobe import HttprobeAdapter
from reconkit.adapters.httpx_tech import HttpxTechAdapter
from reconkit.adapters.httpx_tool import HttpxAdapter
from reconkit.adapters.katana import KatanaAdapter
from reconkit.adapters.masscan import MasscanAdapter
from reconkit.adapters.naabu import NaabuAdapter
from reconkit.adapters.nmap import NmapAdapter
from reconkit.adapters.nuclei import NucleiAdapter
from reconkit.adapters.otx import OtxAdapter
from reconkit.adapters.pyprobe import PyprobeAdapter
from reconkit.adapters.pyscan import PyscanAdapter
from reconkit.adapters.rustscan import RustscanAdapter
from reconkit.adapters.smap import SmapAdapter
from reconkit.adapters.subfinder import SubfinderAdapter
from reconkit.adapters.subjs import SubjsAdapter
from reconkit.adapters.subzy import SubzyAdapter
from reconkit.adapters.tlsx import TlsxAdapter
from reconkit.adapters.unfurl import UnfurlAdapter
from reconkit.adapters.urlfinder import UrlfinderAdapter
from reconkit.adapters.urlscan import UrlscanAdapter
from reconkit.adapters.wafw00f import Wafw00fAdapter
from reconkit.adapters.waybackurls import WaybackurlsAdapter
from reconkit.adapters.webanalyze import WebanalyzeAdapter
from reconkit.adapters.whatweb import WhatwebAdapter

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
    "httprobe": HttprobeAdapter,
    "webanalyze": WebanalyzeAdapter,
    "cdncheck": CdncheckAdapter,
    "waybackurls": WaybackurlsAdapter,
    "hakrawler": HakrawlerAdapter,
    "gospider": GospiderAdapter,
    "subjs": SubjsAdapter,
    "urlfinder": UrlfinderAdapter,
    "unfurl": UnfurlAdapter,
    "wafw00f": Wafw00fAdapter,
    "whatweb": WhatwebAdapter,
    "httpx_tech": HttpxTechAdapter,
    "nuclei": NucleiAdapter,
    "subzy": SubzyAdapter,
    "ffuf": FfufAdapter,
    "nmap": NmapAdapter,
    "rustscan": RustscanAdapter,
    "smap": SmapAdapter,
    "masscan": MasscanAdapter,
    "urlscan": UrlscanAdapter,
    "amass": AmassAdapter,
    "findomain": FindomainAdapter,
    "chaos": ChaosAdapter,
    "github_subdomains": GithubSubdomainsAdapter,
}

__all__ = ["ADAPTERS", "BaseToolAdapter", "BinaryAdapter", "HttpAdapter"]
