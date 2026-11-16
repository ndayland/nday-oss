"""Collector registry. Add new collectors here to expose them to `nday collect`."""

from nday.collectors.base import Collector, NormalizeError
from nday.collectors.cvelist import CveListCollector
from nday.collectors.exploitdb import ExploitDbCollector
from nday.collectors.ghsa import GhsaCollector
from nday.collectors.kev import KevCollector
from nday.collectors.metasploit import MetasploitCollector
from nday.collectors.nuclei import NucleiCollector

COLLECTORS: dict[str, type[Collector]] = {
    KevCollector.name: KevCollector,
    CveListCollector.name: CveListCollector,
    GhsaCollector.name: GhsaCollector,
    ExploitDbCollector.name: ExploitDbCollector,
    MetasploitCollector.name: MetasploitCollector,
    NucleiCollector.name: NucleiCollector,
}

__all__ = [
    "COLLECTORS",
    "Collector",
    "CveListCollector",
    "ExploitDbCollector",
    "GhsaCollector",
    "KevCollector",
    "MetasploitCollector",
    "NormalizeError",
    "NucleiCollector",
]
