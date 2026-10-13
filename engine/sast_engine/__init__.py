"""SAST Sentinel - motor de análise estática de segurança."""

from .models import Finding, ScanResult, Severity, TraceStep
from .scanner import ScanConfig, Scanner

__version__ = "1.0.0"

__all__ = ["Finding", "Severity", "TraceStep", "ScanResult", "Scanner", "ScanConfig", "__version__"]
