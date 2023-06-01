import os
from ._gemini import _Gemini
from functools import wraps
from flask import Flask, Blueprint, request, make_response, render_template, session, redirect, url_for, flash
from ._logger import logger
import ipaddress
from datetime import datetime, timezone
from argon2 import PasswordHasher


class GeminiManager(object):

    def __init__(self, flask_app: Flask = None):

        _Gemini.get_gemini_banner()

        # This is creating a directory called gemini_protector in the current working directory.
        running_directory = os.getcwd()
        gemini_working_directory = os.path.join(
            running_directory, r'gemini_protector')
        if not os.path.exists(gemini_working_directory):
            os.makedirs(gemini_working_directory)

        if not os.path.isfile(gemini_working_directory+'/config.yml'):
            _Gemini.init_gemini_config(gemini_working_directory)

        if not os.path.isfile(gemini_working_directory+'/data.json'):
            _Gemini.init_gemini_data_store(gemini_working_directory)

        if not os.path.isfile(gemini_working_directory+'/acl.json'):
            _Gemini.init_gemini_acl(gemini_working_directory)

        if not os.path.isfile(gemini_working_directory+'/audit_dependency.json'):
            _Gemini.init_gemini_audit_dependency(gemini_working_directory)

        # Register this extension with the flask app now (if it is provided)
        if flask_app is not None:
            self.init_flask_app(flask_app)

    def init_flask_app(self, flask_app: Flask) -> None:
        # Create a blueprint for the nested Flask service
        nested_service = Blueprint('nested_service', __name__)

        if flask_app.secret_key is None:
            flask_app.secret_key = _Gemini.get_gemini_config(
                'gemini_secret_key')

        if flask_app.template_folder and flask_app.static_folder:
            if _Gemini.get_gemini_config('gemini_app_path') is None:
                _Gemini.init_gemini_app_path()

            _Gemini.init_gemini_dashboard(
                flask_app.template_folder, flask_app.static_folder)

            gemini_app_path = _Gemini.get_gemini_config('gemini_app_path')
            logger.info(
                "[+] Access Your Gemini Dashboard as Path: http://0.0.0.0:port/{0}".format(gemini_app_path))

            @nested_service.route('/', methods=['GET', 'POST'])
            def gemini_init():
                try:
                    isInstall = _Gemini.get_gemini_config('gemini_install')
                    if isInstall:
                        if session.get('gemini_logged_in'):
                            return redirect(url_for('nested_service.gemini_dashboard'))
                        else:
                            return redirect(url_for('nested_service.gemini_login'))
                    else:
                        return redirect(url_for('nested_service.gemini_install'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_init', e))

            @nested_service.route('/install', methods=['GET', 'POST'])
            def gemini_install():
                try:
                    isInstall = _Gemini.get_gemini_config('gemini_install')
                    if isInstall:
                        return redirect(url_for('nested_service.gemini_dashboard'))
                    else:
                        if request.method == 'GET':
                            sensitive_value = _Gemini.get_gemini_config(
                                'gemini_sensitive_value')
                            app_path = _Gemini.get_gemini_config(
                                'gemini_app_path')
                            return render_template('gemini_protector_template/install.html',
                                                   _sensitive_value=sensitive_value,
                                                   _app_path=app_path)
                        elif request.method == 'POST':
                            protect_mode = request.form['radio-mode']
                            sensitive_value = request.form['sensitive-value']
                            app_path = request.form['gemini-app-path']
                            password = request.form['pwd']
                            confirm_password = request.form['cpwd']
                            notification_channel = request.form['radio-channel']
                            license_key = request.form['license-key']
                            telegram_token = ''
                            telegram_chat_id = ''
                            notification_webhook = ''
                            if notification_channel == 'disable':
                                notification_channel = 'disable'
                            elif notification_channel == 'telegram':
                                telegram_token = request.form['telegram-token']
                                telegram_chat_id = request.form['telegram-chat-id']
                            else:
                                notification_webhook = request.form['channel-webhook']

                            if _Gemini.validator_protect_mode(protect_mode) and _Gemini.validator_sensitive_value(sensitive_value) and _Gemini.validator_app_path(app_path) and _Gemini.validator_dashboard_password(password, confirm_password) and _Gemini.validator_notification_channel(notification_channel) and _Gemini.validator_license_key(license_key):
                                ph = PasswordHasher()
                                _Gemini.update_gemini_config({
                                    "gemini_install": True,
                                    "gemini_global_protect_mode": protect_mode,
                                    "gemini_sensitive_value": int(sensitive_value),
                                    "gemini_dashboard_path": app_path,
                                    "gemini_notification_channel": notification_channel,
                                    "gemini_telegram_token": telegram_token,
                                    "gemini_telegram_chat_id": telegram_chat_id,
                                    "gemini_notification_webhook": notification_webhook,
                                    "gemini_license_key": license_key,
                                    "gemini_dashboard_password": ph.hash(password),
                                })
                                logger.info(
                                    "[+] Install gemini-self-protector successful.!")
                                return redirect(url_for('nested_service.gemini_login'))
                            else:
                                return redirect(url_for('nested_service.gemini_install'))
                            return redirect(url_for('nested_service.gemini_install'))
                        else:
                            return redirect(url_for('nested_service.gemini_install'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_install', e))

            @nested_service.route('/login', methods=['GET', 'POST'])
            def gemini_login():
                try:
                    isInstall = _Gemini.get_gemini_config('gemini_install')
                    if isInstall:
                        if request.method == 'GET' and session.get('gemini_logged_in'):
                            return redirect(url_for('nested_service.gemini_dashboard'))
                        elif request.method == 'POST':
                            password = request.form['password']
                            ph = PasswordHasher()
                            hash_password = _Gemini.get_gemini_config(
                                'gemini_dashboard_password')
                            if ph.verify(hash_password, password):
                                logger.info("[+] Login successful.!")
                                session['gemini_logged_in'] = True
                                return redirect(url_for('nested_service.gemini_dashboard'))
                            else:
                                return render_template('gemini_protector_template/login.html', error="Incorrect Password")
                        else:
                            return render_template('gemini_protector_template/login.html')
                    else:
                        return redirect(url_for('nested_service.gemini_install'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_login', e))

            @nested_service.route('/dashboard')
            def gemini_dashboard():
                try:
                    if session.get('gemini_logged_in'):
                        normal_request = _Gemini.get_gemini_config(
                            'gemini_normal_request')
                        abnormal_request = _Gemini.get_gemini_config(
                            'gemini_abnormal_request')
                        sensitive_value = _Gemini.get_gemini_config(
                            'gemini_sensitive_value')
                        global_protect_mode = _Gemini.get_gemini_config(
                            'gemini_global_protect_mode')
                        max_content_length = _Gemini.get_gemini_config(
                            'gemini_max_content_length')
                        http_method_allow = _Gemini.get_gemini_config(
                            'gemini_http_method_allow')
                        safe_redirect_status = _Gemini.get_gemini_config(
                            'gemini_safe_redirect')
                        trust_domain_list = _Gemini.get_gemini_config(
                            'gemini_trust_domain')
                        load_data_log = _Gemini.load_gemini_log()
                        load_data_store = _Gemini.load_gemini_data_store()
                        load_data_acl = _Gemini.load_gemini_acl()
                        dependency_file = _Gemini.get_dependency_file()
                        dependency_result = _Gemini.load_gemini_dependency_result()
                        return render_template('gemini_protector_template/dashboard.html',
                                               _protect_mode=global_protect_mode,
                                               _normal_request=normal_request,
                                               _abnormal_request=abnormal_request,
                                               _sensitive_value=sensitive_value,
                                               _gemini_log=load_data_log,
                                               _gemini_data_store=load_data_store,
                                               _gemini_acl=load_data_acl,
                                               _max_content_length=int(
                                                   max_content_length / 1024 / 1024),
                                               _http_method=http_method_allow,
                                               _safe_redirect_status=safe_redirect_status,
                                               _trust_domain_list=", ".join(
                                                   trust_domain_list),
                                               _gemini_dependency_file=dependency_file,
                                               _gemini_dependency_result=dependency_result
                                               )
                    else:
                        logger.warning("[!] Unauthentication Access.!")
                        flash('Please login')
                        return redirect(url_for('nested_service.gemini_login'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_dashboard', e))

            @nested_service.route('/update-config', methods=['POST'])
            def gemini_update_config():
                try:
                    if session.get('gemini_logged_in'):
                        protect_mode = request.form['protect_mode']
                        sensitive_value = request.form['sensitive_value']
                        max_content_length = request.form['max_content_length']
                        http_method = request.form.getlist('http_method[]')
                        safe_redirect_status = request.form['safe_redirect_status']
                        trust_domain_list = request.form.get(
                            'trust_domain_list').split(',')
                        trust_domain_list = [d.strip()
                                             for d in trust_domain_list]

                        if _Gemini.validator_protect_mode(protect_mode) and _Gemini.validator_sensitive_value(sensitive_value) and max_content_length.isdigit() and _Gemini.validator_http_method(http_method) and _Gemini.validator_safe_redirect_status(safe_redirect_status) and _Gemini.validator_trust_domain(trust_domain_list):
                            _Gemini.update_gemini_config({
                                "gemini_global_protect_mode": protect_mode,
                                "gemini_sensitive_value": int(sensitive_value),
                                "gemini_max_content_length": int(max_content_length) * 1024 * 1024,
                                "gemini_http_method_allow": http_method,
                                "gemini_safe_redirect": safe_redirect_status,
                                "gemini_trust_domain": trust_domain_list
                            })
                            logger.info(
                                "[+] Update configuration successfully.!")
                            flash('Update configuration successfully!')
                            return redirect(url_for('nested_service.gemini_dashboard'))
                        else:
                            logger.error(
                                "[x_x] Update configuration unsuccessfully.!")
                            flash('Cannot update config with your input')
                            return redirect(url_for('nested_service.gemini_dashboard'))
                    else:
                        logger.warning("[!] Unauthentication Access.!")
                        flash('Please login')
                        return redirect(url_for('nested_service.gemini_login'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_update_config', e))

            @nested_service.route('/update-acl', methods=['POST'])
            def gemini_update_acl():
                try:
                    if session.get('gemini_logged_in'):
                        ip_address = request.form['ip_address']
                        ip = ipaddress.ip_address(ip_address)

                        if ip:
                            _dict = {"Ip": str(ip), "Time": str(
                                datetime.now(timezone.utc))}
                            _Gemini.update_gemini_acl(_dict)
                            logger.info(
                                "[+] Update acl successfully.!".format(ip_address))
                            flash('Update acl successfully!')
                            return redirect(url_for('nested_service.gemini_dashboard'))
                        else:
                            logger.info(
                                "[+] IP address {} is not valid".format(ip_address))
                            flash('Cannot update acl with your input')
                            return redirect(url_for('nested_service.gemini_dashboard'))
                    else:
                        logger.warning("[!] Unauthentication Access.!")
                        flash('Please login')
                        return redirect(url_for('nested_service.gemini_login'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_update_acl', e))

            @nested_service.route('/remove-acl', methods=['POST'])
            def gemini_remove_acl():
                try:
                    if session.get('gemini_logged_in'):
                        ip_address = request.form['ip_address']
                        ip = ipaddress.ip_address(ip_address)

                        if ip:
                            _Gemini.remove_gemini_acl(str(ip))
                            logger.info("[+] Remove acl successfully.!")
                            return redirect(url_for('nested_service.gemini_dashboard'))
                        else:
                            logger.info(
                                "[+] IP address {} is not valid".format(ip_address))
                            flash('Cannot remove acl with your input.')
                            return redirect(url_for('nested_service.gemini_dashboard'))
                    else:
                        logger.warning("[!] Unauthentication Access.!")
                        flash('Please login')
                        return redirect(url_for('nested_service.gemini_login'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_remove_acl', e))

            @nested_service.route('/dependency-vulnerability', methods=['POST'])
            def gemini_dependency_audit():
                try:
                    if session.get('gemini_logged_in'):
                        file_path = request.form['dependency_path']
                        filename = os.path.basename(file_path)
                        if filename == 'requirements.txt':
                            _Gemini.__audit_dependency_vulnerability__(
                                file_path)
                            return redirect(url_for('nested_service.gemini_dashboard'))
                        else:
                            logger.info(
                                "[+] This {} is not valid requirement file".format(file_path))
                            flash('Cannot dependency audit with your input.')
                            return redirect(url_for('nested_service.gemini_dashboard'))
                    else:
                        logger.warning("[!] Unauthentication Access.!")
                        flash('Please login')
                        return redirect(url_for('nested_service.gemini_login'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_dependency_audit', e))

            @nested_service.route('/logout')
            def gemini_logout():
                try:
                    session['gemini_logged_in'] = False
                    flash('Logout successfully!')
                    return redirect(url_for('nested_service.gemini_login'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_logout', e))

            # Register the blueprint with the main application
            flask_app.register_blueprint(
                nested_service, url_prefix='/'+gemini_app_path)

            # Make secure cookie
            # _Gemini.make_secure_cookie(flask_app)

    def flask_protect_extended(self, protect_mode=None) -> None:
        """
        This function is used to protect the Flask application from malicious requests

        :param protect_mode: This is the mode you want to use for the protection
        :return: The function is being returned.
        """
        def _gemini_self_protect(f):
            @wraps(f)
            def __gemini_self_protect(*args, **kwargs):
                _ip_address = _Gemini.get_flask_client_ip()
                if _Gemini.check_gemini_acl(_ip_address):
                    _ticket = _Gemini.generate_insident_ticket()
                    response = make_response("Your IP Address was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(
                        _ticket["Time"], _ticket["IP"], _ticket["IncidentID"]), 200)
                    response = _Gemini.make_secure_response_header(response)
                    return response
                else:
                    global_protect_mode = _Gemini.get_gemini_config(
                        'gemini_global_protect_mode')
                    if protect_mode is None:
                        gemini_protect_mode = global_protect_mode
                    elif protect_mode is not None and global_protect_mode == 'off':
                        gemini_protect_mode = 'off'
                    else:
                        gemini_protect_mode = protect_mode
                    protect_request = _Gemini.__load_protect_flask_request__(
                        gemini_protect_mode)
                    if protect_request["Status"]:
                        response = make_response(f(*args, **kwargs))
                        protect_response = _Gemini.__load_protect_flask_response__(
                            response, gemini_protect_mode)
                        if protect_response["Status"]:
                            response = _Gemini.make_secure_response_header(
                                response)
                            return response
                        else:
                            current_time = protect_response["Ticket"]["Time"]
                            ip_address = protect_response["Ticket"]["IP"]
                            incedent_id = protect_response["Ticket"]["IncidentID"]
                            response = make_response("This request was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(
                                current_time, ip_address, incedent_id), 200)
                            response = _Gemini.make_secure_response_header(
                                response)
                            return response
                    else:
                        current_time = protect_request["Ticket"]["Time"]
                        ip_address = protect_request["Ticket"]["IP"]
                        incedent_id = protect_request["Ticket"]["IncidentID"]
                        response = make_response("This request was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(
                            current_time, ip_address, incedent_id), 200)
                        response = _Gemini.make_secure_response_header(
                            response)
                        return response
            return __gemini_self_protect
        return _gemini_self_protect

    def django_protect_extended(self):
        return True
