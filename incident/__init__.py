"""
incident/__init__.py

Incident correlation and investigation module for Network Analyzer.
"""
from incident.model import Incident, IncidentStatus
from incident.correlator import IncidentCorrelator

__all__ = ["Incident", "IncidentStatus", "IncidentCorrelator"]