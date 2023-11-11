from flask import session, request
from ._logger import logger
from ._gemini import _Gemini
from ._utils import _Utils


class _Behavior(object):
    def init_behavior() -> None:
        if "gemini_session" not in session:
            client_ip = _Utils.flask_client_ip()
            session["gemini_session"] = hash(client_ip + request.user_agent.string)
        behavior_id = _Behavior.end_user(request.endpoint)
        return behavior_id

    def end_user(action) -> None:
        end_user_ip = _Utils.flask_client_ip()
        g_session = session.get("gemini_session")
        method = request.method
        size = request.content_length
        behavior_id = _Gemini.store_gemini_behavior_log(
            end_user_ip, g_session, action, method, None, None, None, size, None
        )
        return behavior_id
