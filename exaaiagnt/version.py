from importlib.metadata import PackageNotFoundError, version as _v
try:
    __version__ = _v("exaai-agent")
except PackageNotFoundError:
    __version__ = "3.0.0"
