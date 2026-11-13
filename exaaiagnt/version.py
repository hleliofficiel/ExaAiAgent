from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _v


try:
    __version__ = _v("exaai-agent")
except PackageNotFoundError:
    __version__ = "3.2.0"
