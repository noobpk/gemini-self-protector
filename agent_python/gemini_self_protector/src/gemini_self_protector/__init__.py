# read version from installed package
from importlib.metadata import version
__version__ = version("gemini_self_protector")

from .gemini_self_protector import GeminiManager
from ._gemini import _Gemini
from ._logger import logger
from ._utils import _Utils
from ._template import _Template