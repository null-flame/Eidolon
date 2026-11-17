try:
    from importlib.metadata import version, PackageNotFoundError
    try:
        __version__ = version("eidolon-core")
    except PackageNotFoundError:
        # Fallback for local development if not installed via pip
        __version__ = "3.3.0"
except ImportError:
    # For Python < 3.8
    __version__ = "3.3.0"

CODENAME = "SÉANCE"