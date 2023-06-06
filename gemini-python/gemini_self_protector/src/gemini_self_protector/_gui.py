from flask import Flask, Blueprint, request, make_response, render_template, session, redirect, url_for, flash
from ._logger import logger
from ._gemini import _Gemini
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from argon2 import PasswordHasher


class _Gemini_GUI(object):

    def __init__(self, flask_app: Flask) -> None:
        login_manager = LoginManager()
        # Create a blueprint for the nested Flask service
        nested_service = Blueprint(
            'nested_service', __name__, template_folder="templates", static_folder='static')

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
                        if _Gemini.is_valid_license_key():
                            if session.get('gemini_logged_in'):
                                return redirect(url_for('nested_service.gemini_dashboard'))
                            else:
                                return redirect(url_for('nested_service.gemini_login'))
                        else:
                            return redirect(url_for('nested_service.gemini_update_key'))
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
                        if request.method == 'POST':
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
                                    "gemini_app_path": app_path,
                                    "gemini_notification_channel": notification_channel,
                                    "gemini_telegram_token": telegram_token,
                                    "gemini_telegram_chat_id": telegram_chat_id,
                                    "gemini_notification_webhook": notification_webhook,
                                    "gemini_app_password": ph.hash(password),
                                })
                                logger.info(
                                    "[+] Install gemini-self-protector successful.!")
                                return redirect(url_for('nested_service.gemini_login'))
                        else:
                            sensitive_value = _Gemini.get_gemini_config(
                                'gemini_sensitive_value')
                            app_path = _Gemini.get_gemini_config(
                                'gemini_app_path')
                            return render_template('gemini-protector-gui/install.html', _sensitive_value=sensitive_value, _app_path=app_path)
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_install', e))

            @nested_service.route('/update-key', methods=['GET', 'POST'])
            def gemini_update_key():
                try:
                    isInstall = _Gemini.get_gemini_config('gemini_install')
                    if isInstall:
                        if request.method == 'POST':
                            key = request.form['key']
                            if _Gemini.validator_license_key(key):
                                return redirect(url_for('nested_service.gemini_dashboard'))
                            else:
                                return render_template('gemini-protector-gui/license.html', msg="Invalid license key")
                        else:
                            return render_template('gemini-protector-gui/license.html')
                    else:
                        return redirect(url_for('nested_service.gemini_install'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_update_key', e))

            @nested_service.route('/login', methods=['GET', 'POST'])
            def gemini_login():
                try:
                    isInstall = _Gemini.get_gemini_config('gemini_install')
                    if isInstall:
                        if _Gemini.is_valid_license_key():
                            if request.method == 'GET' and session.get('gemini_logged_in'):
                                return redirect(url_for('nested_service.gemini_dashboard'))
                            elif request.method == 'POST':
                                username = request.form['username']
                                password = request.form['password']
                                ph = PasswordHasher()
                                app_username = _Gemini.get_gemini_config(
                                    'gemini_app_username')
                                app_password = _Gemini.get_gemini_config(
                                    'gemini_app_password')
                                if username == app_username and ph.verify(app_password, password):
                                    logger.info("[+] Login successful.!")
                                    session['gemini_logged_in'] = True
                                    return redirect(url_for('nested_service.gemini_dashboard'))
                                else:
                                    return render_template('gemini-protector-gui/accounts/login.html', msg="Incorrect Username / Password")
                            else:
                                return render_template('gemini-protector-gui/accounts/login.html')
                        else:
                            return redirect(url_for('nested_service.gemini_update_key'))
                    else:
                        return redirect(url_for('nested_service.gemini_install'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_login', e))

            @nested_service.route('/profile')
            def gemini_profile():
                try:
                    if _Gemini.is_valid_license_key():
                        if request.method == 'POST':
                            password = request.form['pwd']
                            confirm_password = request.form['cpwd']

                            if _Gemini.validator_dashboard_password(password, confirm_password):
                                ph = PasswordHasher()
                                _Gemini.update_gemini_config({
                                    "gemini_app_password": ph.hash(password),
                                })
                                logger.info(
                                    "[+] Update password successful.")
                                return redirect(url_for('nested_service.gemini_login'))
                            else:
                                return render_template('gemini-protector-gui/home/profile.html', msg="Invalid password")
                        else:
                            app_username = _Gemini.get_gemini_config(
                                'gemini_app_username')

                            return render_template('gemini-protector-gui/home/profile.html', _username=app_username,)
                    else:
                        return redirect(url_for('nested_service.gemini_update_key'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_profile', e))

            @nested_service.route('/dashboard')
            def gemini_dashboard():
                try:
                    if _Gemini.is_valid_license_key():
                        if session.get('gemini_logged_in'):
                            total_request = _Gemini.get_gemini_config(
                                'gemini_total_request')
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
                            server_name = _Gemini.get_gemini_config(
                                'gemini_server_name')
                            http_method_allow = _Gemini.get_gemini_config(
                                'gemini_http_method_allow')
                            safe_redirect_status = _Gemini.get_gemini_config(
                                'gemini_safe_redirect')
                            trust_domain_list = _Gemini.get_gemini_config(
                                'gemini_trust_domain')
                            app_username = _Gemini.get_gemini_config(
                                'gemini_app_username')
                            # load_data_log = _Gemini.load_gemini_log()
                            # load_data_store = _Gemini.load_gemini_data_store()
                            # load_data_acl = _Gemini.load_gemini_acl()
                            # dependency_file = _Gemini.get_dependency_file()
                            # dependency_result = _Gemini.load_gemini_dependency_result()
                            return render_template('gemini-protector-gui/home/index.html',
                                                   _username=app_username,
                                                   _protect_mode=global_protect_mode,
                                                   _total_request=total_request,
                                                   _normal_request=normal_request,
                                                   _abnormal_request=abnormal_request,
                                                   _sensitive_value=sensitive_value,
                                                   _server_name=server_name,
                                                   # _gemini_log=load_data_log,
                                                   # _gemini_data_store=load_data_store,
                                                   # _gemini_acl=load_data_acl,
                                                   _max_content_length=int(
                                                       max_content_length / 1024 / 1024),
                                                   _http_method=http_method_allow,
                                                   _safe_redirect_status=safe_redirect_status,
                                                   _trust_domain_list=", ".join(
                                                       trust_domain_list),
                                                   # _gemini_dependency_file=dependency_file,
                                                   # _gemini_dependency_result=dependency_result
                                                   )
                        else:
                            logger.warning("[!] Unauthentication Access.!")
                            flash('Please login')
                            return redirect(url_for('nested_service.gemini_login'))
                    else:
                        return redirect(url_for('nested_service.gemini_update_key'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_dashboard', e))

            # @nested_service.route('/update-config', methods=['POST'])
            # def gemini_update_config():
            #     try:
            #         if _Gemini.is_valid_license_key():
            #             if session.get('gemini_logged_in'):
            #                 protect_mode = request.form['protect_mode']
            #                 sensitive_value = request.form['sensitive_value']
            #                 max_content_length = request.form['max_content_length']
            #                 http_method = request.form.getlist('http_method[]')
            #                 safe_redirect_status = request.form['safe_redirect_status']
            #                 trust_domain_list = request.form.get(
            #                     'trust_domain_list').split(',')
            #                 trust_domain_list = [d.strip()
            #                                     for d in trust_domain_list]

            #                 if _Gemini.validator_protect_mode(protect_mode) and _Gemini.validator_sensitive_value(sensitive_value) and max_content_length.isdigit() and _Gemini.validator_http_method(http_method) and _Gemini.validator_safe_redirect_status(safe_redirect_status) and _Gemini.validator_trust_domain(trust_domain_list):
            #                     _Gemini.update_gemini_config({
            #                         "gemini_global_protect_mode": protect_mode,
            #                         "gemini_sensitive_value": int(sensitive_value),
            #                         "gemini_max_content_length": int(max_content_length) * 1024 * 1024,
            #                         "gemini_http_method_allow": http_method,
            #                         "gemini_safe_redirect": safe_redirect_status,
            #                         "gemini_trust_domain": trust_domain_list
            #                     })
            #                     logger.info(
            #                         "[+] Update configuration successfully.!")
            #                     flash('Update configuration successfully!')
            #                     return redirect(url_for('nested_service.gemini_dashboard'))
            #                 else:
            #                     logger.error(
            #                         "[x_x] Update configuration unsuccessfully.!")
            #                     flash('Cannot update config with your input')
            #                     return redirect(url_for('nested_service.gemini_dashboard'))
            #             else:
            #                 logger.warning("[!] Unauthentication Access.!")
            #                 flash('Please login')
            #                 return redirect(url_for('nested_service.gemini_login'))
            #         else:
            #             return redirect(url_for('nested_service.gemini_update_key'))
            #     except Exception as e:
            #         logger.error(
            #             "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_update_config', e))

            # @nested_service.route('/update-acl', methods=['POST'])
            # def gemini_update_acl():
            #     try:
            #         if _Gemini.is_valid_license_key():
            #             if session.get('gemini_logged_in'):
            #                 ip_address = request.form['ip_address']
            #                 ip = ipaddress.ip_address(ip_address)

            #                 if ip:
            #                     _dict = {"Ip": str(ip), "Time": str(
            #                         datetime.now(timezone.utc))}
            #                     _Gemini.update_gemini_acl(_dict)
            #                     logger.info(
            #                         "[+] Update acl successfully.!".format(ip_address))
            #                     flash('Update acl successfully!')
            #                     return redirect(url_for('nested_service.gemini_dashboard'))
            #                 else:
            #                     logger.info(
            #                         "[+] IP address {} is not valid".format(ip_address))
            #                     flash('Cannot update acl with your input')
            #                     return redirect(url_for('nested_service.gemini_dashboard'))
            #             else:
            #                 logger.warning("[!] Unauthentication Access.!")
            #                 flash('Please login')
            #                 return redirect(url_for('nested_service.gemini_login'))
            #         else:
            #             return redirect(url_for('nested_service.gemini_update_key'))
            #     except Exception as e:
            #         logger.error(
            #             "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_update_acl', e))

            # @nested_service.route('/remove-acl', methods=['POST'])
            # def gemini_remove_acl():
            #     try:
            #         if _Gemini.is_valid_license_key():
            #             if session.get('gemini_logged_in'):
            #                 ip_address = request.form['ip_address']
            #                 ip = ipaddress.ip_address(ip_address)

            #                 if ip:
            #                     _Gemini.remove_gemini_acl(str(ip))
            #                     logger.info("[+] Remove acl successfully.!")
            #                     return redirect(url_for('nested_service.gemini_dashboard'))
            #                 else:
            #                     logger.info(
            #                         "[+] IP address {} is not valid".format(ip_address))
            #                     flash('Cannot remove acl with your input.')
            #                     return redirect(url_for('nested_service.gemini_dashboard'))
            #             else:
            #                 logger.warning("[!] Unauthentication Access.!")
            #                 flash('Please login')
            #                 return redirect(url_for('nested_service.gemini_login'))
            #         else:
            #             return redirect(url_for('nested_service.gemini_update_key'))
            #     except Exception as e:
            #         logger.error(
            #             "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_remove_acl', e))

            # @nested_service.route('/dependency-vulnerability', methods=['POST'])
            # def gemini_dependency_audit():
            #     try:
            #         if _Gemini.is_valid_license_key():
            #             if session.get('gemini_logged_in'):
            #                 file_path = request.form['dependency_path']
            #                 filename = os.path.basename(file_path)
            #                 if filename == 'requirements.txt':
            #                     _Gemini.__audit_dependency_vulnerability__(
            #                         file_path)
            #                     return redirect(url_for('nested_service.gemini_dashboard'))
            #                 else:
            #                     logger.info(
            #                         "[+] This {} is not valid requirement file".format(file_path))
            #                     flash('Cannot dependency audit with your input.')
            #                     return redirect(url_for('nested_service.gemini_dashboard'))
            #             else:
            #                 logger.warning("[!] Unauthentication Access.!")
            #                 flash('Please login')
            #                 return redirect(url_for('nested_service.gemini_login'))
            #         else:
            #             return redirect(url_for('nested_service.gemini_update_key'))
            #     except Exception as e:
            #         logger.error(
            #             "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_dependency_audit', e))

            @nested_service.route('/logout')
            def gemini_logout():
                try:
                    session['gemini_logged_in'] = False
                    flash('Logout successfully!')
                    return redirect(url_for('nested_service.gemini_login'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_logout', e))

            @login_manager.unauthorized_handler
            def unauthorized_handler():
                return render_template('gemini-protector-gui/home/page-403.html'), 403

            @nested_service.errorhandler(403)
            def access_forbidden(error):
                return render_template('gemini-protector-gui/home/page-403.html'), 403

            @nested_service.errorhandler(404)
            def not_found_error(error):
                return render_template('gemini-protector-gui/home/page-404.html'), 404

            @nested_service.errorhandler(500)
            def internal_error(error):
                return render_template('gemini-protector-gui/home/page-500.html'), 500

            # Register the blueprint with the main application
            flask_app.register_blueprint(
                nested_service, url_prefix='/'+gemini_app_path)
