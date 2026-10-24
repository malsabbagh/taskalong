"""Compatibility entry points for the shipped 2.5 private capture contract.

Shared validation lives in the neutral module; its registry preserves the exact
Cursor field names, observation bytes, error codes and finish-request identity.
"""
from .observed_capture import retain_handoff, validate_handoff, validate_completed_run
