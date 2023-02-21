import os
from ._gemini import _Gemini
from functools import wraps
from flask import Flask, request, make_response, render_template, session, redirect, url_for, flash
from ._logger import logger
import ipaddress
from datetime import datetime, timezone

class GeminiManager(object):

    def __init__(self, flask_app: Flask = None, license_key="w"):
        """
        This function is used to initialize the class.

        :param flask_app: This is the flask app that you want to protect
        :type flask_app: Flask
        :param license_key: This is the license key that you will be using to protect your application,
        defaults to w (optional)
        :param protect_mode: This is the mode of protection you want to use, defaults to w (optional)
        :param sensitive_value: This is the value that you want to protect, defaults to w (optional)
        """

        # This is creating a directory called gemini_protector in the current working directory.
        running_directory = os.getcwd()
        gemini_working_directory = os.path.join(running_directory, r'gemini_protector')
        if not os.path.exists(gemini_working_directory):
            os.makedirs(gemini_working_directory)

        if not os.path.isfile(gemini_working_directory+'/config.yml'):
            _Gemini.init_gemini_config(gemini_working_directory)
            _Gemini.validator_license_key(license_key)

        if not os.path.isfile(gemini_working_directory+'/data.json'):
            _Gemini.init_gemini_data_store(gemini_working_directory)

        if not os.path.isfile(gemini_working_directory+'/acl.json'):
            _Gemini.init_gemini_acl(gemini_working_directory)

        # Register this extension with the flask app now (if it is provided)
        if flask_app is not None:
            self.init_flask_app(flask_app)

    def init_flask_app(self, flask_app: Flask) -> None:
        if flask_app.secret_key is None:
            flask_app.secret_key = _Gemini.get_gemini_config('gemini_secret_key')

        if flask_app.template_folder and flask_app.static_folder:
            if _Gemini.get_gemini_config('gemini_dashboard_path') is None:
                _Gemini.init_gemini_dashboard_path()
                _Gemini.init_gemini_dashboard_password()

            _Gemini.init_gemini_dashboard(flask_app.template_folder, flask_app.static_folder)
            dashboard_path = _Gemini.get_gemini_config('gemini_dashboard_path')
            logger.info("[+] Access Your Gemini Dashboard as Path: http://host:port/{}/dashboard".format(dashboard_path))
            logger.info("[+] Check the config file at gemini_protector/config.yml/config.yaml for the password.")

            @flask_app.route('/'+dashboard_path, methods=['GET', 'POST'])
            def gemini_init():
                try:
                    if session.get('gemini_logged_in'):
                        return redirect(url_for('gemini_dashboard'))
                    else:
                        return redirect(url_for('gemini_login'))
                except Exception as e:
                    logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
            @flask_app.route('/'+dashboard_path+'/login', methods=['GET', 'POST'])
            def gemini_login():
                try:
                    if request.method == 'GET' and session.get('gemini_logged_in'):
                        return redirect(url_for('gemini_dashboard'))
                    elif request.method == 'POST':
                        password = request.form['password']
                        secret_password = _Gemini.get_gemini_config('gemini_dashboard_password')
                        if password == secret_password:
                            logger.info("[+] Login sucessfully.!")
                            session['gemini_logged_in'] = True
                            return redirect(url_for('gemini_dashboard'))
                        else:
                            return render_template('gemini_protector_template/login.html', error="Incorrect Password")
                    else:
                        return render_template('gemini_protector_template/login.html')
                except Exception as e:
                    logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
            @flask_app.route('/'+dashboard_path+'/dashboard')
            def gemini_dashboard():
                try:
                    if session.get('gemini_logged_in'):
                        normal_request = _Gemini.get_gemini_config('gemini_normal_request')
                        abnormal_request = _Gemini.get_gemini_config('gemini_abnormal_request')
                        sensitive_value = _Gemini.get_gemini_config('gemini_sensitive_value')
                        global_protect_mode = _Gemini.get_gemini_config('gemini_global_protect_mode')
                        max_content_length = _Gemini.get_gemini_config('gemini_max_content_length')
                        http_method_allow = _Gemini.get_gemini_config('gemini_http_method_allow')
                        safe_redirect_status = _Gemini.get_gemini_config('gemini_safe_redirect')
                        trust_domain_list = _Gemini.get_gemini_config('gemini_trust_domain')
                        load_data_log = _Gemini.load_gemini_log()
                        load_data_store = _Gemini.load_gemini_data_store()
                        load_data_acl = _Gemini.load_gemini_acl()
                        return render_template('gemini_protector_template/dashboard.html',
                            _protect_mode=global_protect_mode,
                            _normal_request=normal_request,
                            _abnormal_request=abnormal_request,
                            _sensitive_value=sensitive_value,
                            _gemini_log=load_data_log,
                            _gemini_data_store=load_data_store,
                            _gemini_acl=load_data_acl,
                            _max_content_length=int(max_content_length / 1024 / 1024),
                            _http_method=http_method_allow,
                            _safe_redirect_status=safe_redirect_status,
                            _trust_domain_list=", ".join(trust_domain_list)
                            )
                    else:
                        logger.warning("[!] Unauthentication Access.!")
                        flash('Please login')
                        return redirect(url_for('gemini_login'))
                except Exception as e:
                    logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
            @flask_app.route('/'+dashboard_path+'/update-config', methods=['POST'])
            def gemini_update_config():
                try:
                    if session.get('gemini_logged_in'):
                        protect_mode = request.form['protect_mode']
                        sensitive_value = request.form['sensitive_value']
                        max_content_length = request.form['max_content_length']
                        http_method = request.form.getlist('http_method[]')
                        safe_redirect_status = request.form['safe_redirect_status']
                        trust_domain_list = request.form.get('trust_domain_list').split(',')
                        trust_domain_list = [d.strip() for d in trust_domain_list]

                        if _Gemini.validator_protect_mode(protect_mode) and _Gemini.validator_sensitive_value(sensitive_value) and max_content_length.isdigit() and _Gemini.validator_http_method(http_method) and _Gemini.validator_safe_redirect_status(safe_redirect_status) and _Gemini.validator_trust_domain(trust_domain_list):
                            _Gemini.update_gemini_config({
                                "gemini_global_protect_mode": protect_mode,
                                "gemini_sensitive_value": int(sensitive_value),
                                "gemini_max_content_length": int(max_content_length) * 1024 * 1024,
                                "gemini_http_method_allow": http_method,
                                "gemini_safe_redirect": safe_redirect_status,
                                "gemini_trust_domain":trust_domain_list
                                })
                            logger.info("[+] Update configuration successfully.!")
                            flash('Update configuration successfully!')
                            return redirect(url_for('gemini_dashboard'))
                        else:
                            logger.error("[x_x] Update configuration unsuccessfully.!")
                            flash('Cannot update config with your input')
                            return redirect(url_for('gemini_dashboard'))
                    else:
                        logger.warning("[!] Unauthentication Access.!")
                        flash('Please login')
                        return redirect(url_for('gemini_login'))
                except Exception as e:
                    logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

            @flask_app.route('/'+dashboard_path+'/update-acl', methods=['POST'])
            def gemini_update_acl():
                try:
                    if session.get('gemini_logged_in'):
                        ip_address = request.form['ip_address']
                        ip = ipaddress.ip_address(ip_address)

                        if ip:
                            _dict = {"Ip": str(ip), "Time": str(datetime.now(timezone.utc))}
                            _Gemini.update_gemini_acl(_dict)
                            logger.info("[+] Update acl successfully.!".format(ip_address))
                            flash('Update acl successfully!')
                            return redirect(url_for('gemini_dashboard'))
                        else:
                            logger.info("[+] IP address {} is not valid".format(ip_address))
                            flash('Cannot update acl with your input')
                            return redirect(url_for('gemini_dashboard'))
                    else:
                        logger.warning("[!] Unauthentication Access.!")
                        flash('Please login')
                        return redirect(url_for('gemini_login'))
                except Exception as e:
                    logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

            @flask_app.route('/'+dashboard_path+'/remove-acl', methods=['POST'])
            def gemini_remove_acl():
                try:
                    if session.get('gemini_logged_in'):
                        ip_address = request.form['ip_address']
                        ip = ipaddress.ip_address(ip_address)

                        if ip:
                            _Gemini.remove_gemini_acl(str(ip))
                            logger.info("[+] Remove acl successfully.!")
                            return redirect(url_for('gemini_dashboard'))
                        else:
                            logger.info("[+] IP address {} is not valid".format(ip_address))
                            flash('Cannot remove acl with your input.')
                            return redirect(url_for('gemini_dashboard'))
                    else:
                        logger.warning("[!] Unauthentication Access.!")
                        flash('Please login')
                        return redirect(url_for('gemini_login'))
                except Exception as e:
                    logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

            @flask_app.route('/'+dashboard_path+'/logout')
            def gemini_logout():
                try:
                    session['gemini_logged_in'] = False
                    flash('Logout successfully!')
                    return redirect(url_for('gemini_login'))
                except Exception as e:
                    logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def flask_protect_extended(self, protect_mode = None) -> None:
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
                    response = make_response("Your IP Address was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(_ticket["Time"], _ticket["IP"], _ticket["IncidentID"]), 200)
                    response = _Gemini.make_secure_response_header(response)
                    return response
                else:
                    global_protect_mode = _Gemini.get_gemini_config('gemini_global_protect_mode')
                    if protect_mode is None:
                        gemini_protect_mode = global_protect_mode
                    elif protect_mode is not None and global_protect_mode == 'off':
                        gemini_protect_mode = 'off'
                    else:
                        gemini_protect_mode = protect_mode

                    protect_request = _Gemini.__load_protect_flask_request__(gemini_protect_mode)
                    if protect_request["Status"]:
                        response = make_response(f(*args, **kwargs))
                        protect_response = _Gemini.__load_protect_flask_response__(response, gemini_protect_mode)
                        if protect_response["Status"]:
                            response = _Gemini.make_secure_response_header(response)
                            return response
                        else:
                            current_time = protect_response["Ticket"]["Time"]
                            ip_address = protect_response["Ticket"]["IP"]
                            incedent_id = protect_response["Ticket"]["IncidentID"]
                            response =  make_response("This request was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(current_time, ip_address, incedent_id), 200)
                            response = _Gemini.make_secure_response_header(response)
                            return response
                    else:
                        current_time = protect_request["Ticket"]["Time"]
                        ip_address = protect_request["Ticket"]["IP"]
                        incedent_id = protect_request["Ticket"]["IncidentID"]
                        response = make_response("This request was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(current_time, ip_address, incedent_id), 200)
                        response = _Gemini.make_secure_response_header(response)
                        return response
            return __gemini_self_protect
        return _gemini_self_protect

    def django_protect_extended(self):
        return True
