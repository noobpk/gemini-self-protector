# read version from installed package
from importlib.metadata import version
__version__ = version("gemini_self_protector")

from .gemini_self_protector import GeminiManager
from ._gemini import _Gemini
from ._logger import logger
from ._utils import _Utils, _Validator
from ._template import _Template
from ._config import _Config
from ._protect import _Protect
from ._audit import _Audit
from ._gui import _Gemini_GUI
from ._model import Base, tb_User, tb_Config, tb_Summary, tb_RequestLog, tb_AccessControlList, tb_Dependency
from ._cli import _Gemini_CLI