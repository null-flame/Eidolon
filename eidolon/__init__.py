try:
    from importlib.metadata import version, PackageNotFoundError
    try:
        __version__ = version("eidolon-core")
    except PackageNotFoundError:
        # Fallback for local development if not installed via pip
        __version__ = "3.1.10"
except ImportError:
    # For Python < 3.8
    __version__ = "3.1.10"

CODENAME = "SPECTRAL_CORE"