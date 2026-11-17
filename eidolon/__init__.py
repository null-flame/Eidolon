try:
    from importlib.metadata import version, PackageNotFoundError
    try:
        __version__ = version("eidolon-core")
    except PackageNotFoundError:
        # Fallback for local development if not installed via pip
        __version__ = "3.2.1"
except ImportError:
    # For Python < 3.8
    __version__ = "3.2.1"

CODENAME = "GRIMOIRE"