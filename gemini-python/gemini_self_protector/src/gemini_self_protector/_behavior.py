from flask import session, request
from ._logger import logger
from ._gemini import _Gemini
from ._utils import _Utils


class _Behavior(object):
    def init_behavior() -> None:
        if "gemini_session" not in session:
            client_ip = _Utils.flask_client_ip()
            session["gemini_session"] = hash(client_ip + request.user_agent.string)
        id_behavior = _Behavior.end_user(request.endpoint)
        return id_behavior

    def end_user(action) -> None:
        end_user_ip = _Utils.flask_client_ip()
        end_user_session = session.get("gemini_session")
        method = request.method
        size = request.content_length
        id_behavior = _Gemini.store_gemini_behavior_log(
            end_user_ip, end_user_session, action, method, None, None, None, size, None
        )
        return id_behavior
