"""ASGI entrypoint. Missing/invalid configuration yields a fail-closed service."""
from .runtime import build_from_environment

app = build_from_environment()
