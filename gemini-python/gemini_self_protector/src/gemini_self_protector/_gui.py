from flask import Flask, Blueprint, request, render_template, session, redirect, url_for, flash, jsonify, send_file
from ._logger import logger
from ._gemini import _Gemini
import argon2
from datetime import datetime
import ipaddress
import re
import os
import json
import ast
from math import floor
from tqdm import tqdm
import urllib.parse
import sys

ph = argon2.PasswordHasher()

class _Gemini_GUI(object):

    def __init__(self, flask_app: Flask) -> None:
        for i in tqdm(range(100), colour="green", desc="Gemini Loading"):
            pass
        last_running_mode = _Gemini.get_gemini_config().running_mode
        if last_running_mode == 'CLI':
            _Gemini.update_gemini_config({'is_install': 0})
        logger.info(
            "[+] Running gemini-self protector - GUI Mode")
        _Gemini.update_gemini_config({'running_mode': 'GUI'})
        is_install = _Gemini.get_gemini_config().is_install
        if int(is_install) == 1:
            is_use_g_wvd_serve = _Gemini.get_gemini_config().is_use_g_wvd_serve
            if int(is_use_g_wvd_serve) == 1:
                _Gemini_GUI.handler_g_wvd_serve_health()
            else:
                logger.info(
                    "[+] No connection to G-WVD")
        else:
            logger.info(
                    "Welcome to the Gemini self-protector. Visit the link below to install.")
        # @flask_app.before_request
        # def log_request_info():
        #     print("Request Headers:", request.headers)
        #     print('Request Method:', request.method)
        #     print('Request Body:', request.get_data())

        # def count_request_to_service():
        #     _Gemini.calulate_total_access()

        # Create a blueprint for the nested Flask service
        nested_service = Blueprint(
            'nested_service', __name__, template_folder="templates", static_folder='static')

        if flask_app.secret_key is None:
            flask_app.secret_key = _Gemini.get_gemini_config().secret_key

        if flask_app.config.get('MAX_CONTENT_LENGTH') is None:
            flask_app.config.update(
                MAX_CONTENT_LENGTH=_Gemini.get_gemini_config().max_content_length
            )

        if flask_app.template_folder and flask_app.static_folder:
            if _Gemini.get_gemini_config().app_path is None:
                _Gemini.init_gemini_app_path()

            _Gemini.init_gemini_dashboard(
                flask_app.template_folder, flask_app.static_folder)

            gemini_app_path = _Gemini.get_gemini_config().app_path
            logger.info(
                "[+] Access Your Gemini Dashboard as Path: http://host:port/{0}".format(gemini_app_path))

            @nested_service.app_template_filter('gemini_datetime_format')
            def datetime_format(value, format='%d %B %H:%M'):
                if isinstance(value, str):
                    value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
                return value.strftime(format)

            @nested_service.app_template_filter('gemini_round_number')
            def round_number(value, decimals=2):
                multiplier = 10 ** decimals
                return floor(value * multiplier + 0.5) / multiplier

            @nested_service.route('/', methods=['GET', 'POST'])
            def gemini_init():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install):
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
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install):
                        return redirect(url_for('nested_service.gemini_dashboard'))
                    else:
                        if request.method == 'POST':
                            request_data = request.get_json()
                            protect_mode = request.json['radio-protect-mode']
                            if 'checkbox-g-wvd' in request_data:
                                is_use_gwvd = 1
                            else:
                                is_use_gwvd = 0
                            sensitive_value = request.json['sensitive-value']
                            app_path = request.json['basic-url']
                            password = request.json['dashboard-pwd-value']
                            confirm_password = request.json['dashboard-cpwd-value']
                            notification_channel = request.json['notification-channel']
                            g_serve_key = request.json['g-serve-key-value']
                            g_wvd_serve = request.json['g-wvd-serve-value']
                            telegram_token = request.json['telegram-token-value']
                            telegram_chat_id = request.json['telegram-chat-id-value']
                            mattermost_webhook = request.json['mattermost-webhook-value']
                            slack_webhook = request.json['slack-webhook-value']

                            allow_install = False
                            if is_use_gwvd == 1:
                                if _Gemini.validator_sensitive_value(sensitive_value) and _Gemini.validator_g_wvd_serve(g_wvd_serve, g_serve_key):
                                    allow_install = True
                                else:
                                    return jsonify({"status": "Install Error"}), 500

                            if _Gemini.validator_protect_mode(protect_mode) and _Gemini.validator_app_path(app_path) and _Gemini.validator_dashboard_password(password, confirm_password) and _Gemini.validator_notification_channel(notification_channel):
                                allow_install = True
                            else:
                                return jsonify({"status": "Install Error"}), 500

                            if allow_install:
                                _Gemini.update_gemini_config({
                                    "is_install": True,
                                    "running_mode": "GUI",
                                    "is_use_g_wvd_serve": is_use_gwvd,
                                    "global_protect_mode": protect_mode,
                                    "sensitive_value": int(sensitive_value),
                                    "app_path": app_path,
                                    "notification_channel": notification_channel,
                                    "telegram_token": telegram_token,
                                    "telegram_chat_id": telegram_chat_id,
                                    "mattermost_webhook": mattermost_webhook,
                                    "slack_webhook": slack_webhook,
                                    "g_wvd_serve": g_wvd_serve,
                                    "g_serve_key": g_serve_key
                                })
                                _Gemini.update_gemini_user({
                                    "password": ph.hash(password),
                                })
                                logger.info(
                                    "[+] Install gemini-self-protector successful.!")
                                flash(
                                    'Instal gemini-self-protector successful. Login and explore now', 'login')
                                return jsonify({"status": "Install Success"}), 200
                        else:
                            sensitive_value = _Gemini.get_gemini_config().sensitive_value
                            app_path = _Gemini.get_gemini_config().app_path
                            return render_template('gemini-protector-gui/install.html', _sensitive_value=sensitive_value, _app_path=app_path)

                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_install', e))

            @nested_service.route('/update-key', methods=['GET', 'POST'])
            def gemini_update_key():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    if request.method == 'POST':
                        key = request.form['key']
                        if _Gemini.validate_g_serve_key(key):
                            flash('Predict server key auth update successful',
                                  'key_update_success')
                            return redirect(url_for('nested_service.gemini_dashboard'))
                        else:
                            return render_template('gemini-protector-gui/key.html', msg="Invalid predict server key auth")
                    return render_template('gemini-protector-gui/key.html')

                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_update_key', e))

            @nested_service.route('/login', methods=['GET', 'POST'])
            def gemini_login():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        flash('Please install!', 'required')
                        return redirect(url_for('nested_service.gemini_install'))

                    if request.method == 'GET' and session.get('gemini_logged_in'):
                        return redirect(url_for('nested_service.gemini_dashboard'))

                    if request.method == 'POST':
                        username = request.form['username']
                        password = request.form['password']

                        app_username = _Gemini.get_gemini_user().username
                        app_password = _Gemini.get_gemini_user().password

                        try:
                            password_check = ph.verify(app_password, password)
                        except argon2.exceptions.VerifyMismatchError:
                            return render_template('gemini-protector-gui/accounts/login.html', msg="Incorrect Username / Password")
                        
                        if username == app_username and password_check:
                            session['gemini_logged_in'] = True
                            flash('Welcome back {}!'.format(
                                app_username), 'login')
                            return redirect(url_for('nested_service.gemini_dashboard'))
                        else:
                            return render_template('gemini-protector-gui/accounts/login.html', msg="Incorrect Username / Password")
                    return render_template('gemini-protector-gui/accounts/login.html')

                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_login', e))

            @nested_service.route('/profile')
            def gemini_profile():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    if request.method == 'POST':
                        password = request.form['pwd']
                        confirm_password = request.form['cpwd']

                        if not _Gemini.validator_dashboard_password(password, confirm_password):
                            return render_template('gemini-protector-gui/home/profile.html', msg="Invalid password")

                        _Gemini.update_gemini_config({
                            "gemini_app_password": ph.hash(password),
                        })
                        logger.info("[+] Update password successful.")
                        return redirect(url_for('nested_service.gemini_login'))

                    app_username = _Gemini.get_gemini_user().username
                    return render_template('gemini-protector-gui/home/profile.html', _username=app_username)

                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_profile', e))

            @nested_service.route('/dashboard')
            def gemini_dashboard():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        flash('Please install!', 'required')
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    gemini_summary = _Gemini.get_gemini_summary()
                    gemini_config = _Gemini.get_gemini_config()
                    gemini_user = _Gemini.get_gemini_user()
                    request_log = _Gemini.get_gemini_request_log()
                    beharvior_log = _Gemini.get_gemini_behavior_log()
                    # predict_server_status = _Gemini.health_check_predict_server()
                    server_performance = _Gemini.g_server_performance()

                    sorted_request_log_data = sorted(
                        request_log, key=lambda x: x.time)
                    page = int(request.args.get('page', 1))
                    per_page = 5
                    total_records = len(sorted_request_log_data)
                    total_pages = (total_records + per_page - 1) // per_page
                    start_index = (page - 1) * per_page
                    end_index = start_index + per_page
                    limited_request_log_data = sorted_request_log_data[start_index:end_index]
                    
                    attack_counts = {
                        'Malicious Request': 0,
                        'ACL Block': 0,
                        'Malicious Response': 0,
                        'Unvalidated Redirects': 0,
                        'Large Requests': 0,
                        'HTTP Method Tampering': 0,
                        'DOS': 0,
                        'Cross-Site Scripting': 0,
                        'SQL Injection': 0
                    }

                    for log in request_log:
                        attack_type = log.attack_type
                        if attack_type in attack_counts:
                            attack_counts[attack_type] += 1

                    any_attack_count_gt_zero = any(value > 0 for value in attack_counts.values())
                    
                    return render_template('gemini-protector-gui/home/index.html',
                                           _username=gemini_user.username,
                                           _protect_mode=gemini_config.global_protect_mode,
                                           _total_request=gemini_summary.total_request,
                                           _normal_request=gemini_summary.normal_request,
                                           _abnormal_request=gemini_summary.abnormal_request,
                                           _sensitive_value=gemini_config.sensitive_value,
                                           _normal_response=gemini_summary.normal_response,
                                           _abnormal_response=gemini_summary.abnormal_response,
                                           _gemini_request_log_data=limited_request_log_data,
                                           _current_page=page,
                                           _total_pages=total_pages,
                                           _anti_dos=gemini_config.anti_dos,
                                           _max_req_per_min=gemini_config.max_requests_per_minute,
                                           # _gemini_predict_server_status=predict_server_status,
                                           # _gemini_predict_server=gemini_config.predict_server,
                                           _gemini_notification_channel=gemini_config.notification_channel,
                                           _gemini_attack_counts=attack_counts,
                                           _any_attack_count_gt_zero=any_attack_count_gt_zero,
                                           _gemini_beharvior_log_data=beharvior_log,
                                           _server_performance=server_performance
                                           )
                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_dashboard', e))

            @nested_service.route('/monitor', methods=['GET'])
            def gemini_monitor():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    gemini_config = _Gemini.get_gemini_config()
                    return render_template('gemini-protector-gui/home/monitor.html', _socketio=gemini_config.socket_io)

                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_monitor', e))

            @nested_service.route('/configurate', methods=['GET', 'POST'])
            def gemini_configurate():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    if request.method == 'POST':
                        # Get the request data as bytes
                        request_data_bytes = request.get_data()

                        # Convert bytes to a string (assuming UTF-8 encoding)
                        request_data_str = request_data_bytes.decode('utf-8')

                        # Split the string into key-value pairs
                        key_value_pairs = request_data_str.split('&')

                        # Create a dictionary to store the form data
                        form_data = {}

                        # Parse the key-value pairs
                        for pair in key_value_pairs:
                            key, value = pair.split('=')
                            form_data[key] = value

                        anti_dos = form_data['radio-anti-dos-status']
                        max_requests_per_minute = form_data['max-request-per-min']
                        enable_acl = form_data['radio-acl-status']

                        if 'checkbox-g-wvd' in form_data:
                            is_use_gwvd = 1
                        else:
                            is_use_gwvd = 0

                        protect_mode = form_data['radio-protect-mode']
                        sensitive_value = form_data['sensitive-value']
                        g_wvd_serve = form_data['g-wvd-serve-value']
                        decoded_g_wvd_serve = urllib.parse.unquote(g_wvd_serve)
                        g_serve_key = form_data['g-serve-key-value']
                        is_predict_header = form_data['predict_header_status']
                        max_content_length = form_data['max_content_length']
                        http_method = request.form.getlist('http_method[]')
                        protect_response = form_data['protect_response_status']
                        safe_redirect = form_data['safe_redirect_status']
                        trust_domain_list = [d.strip() for d in request.form.get(
                            'trust_domain_list').split(',')]
                        socket_io = form_data['socketio']

                        allow_update_config = False

                        if _Gemini.validator_protect_mode(protect_mode) and max_content_length.isdigit() and _Gemini.validator_http_method(http_method) and _Gemini.validator_on_off_status(safe_redirect) and _Gemini.validator_trust_domain(trust_domain_list) and _Gemini.validator_on_off_status(protect_response) and _Gemini.validator_on_off_status(enable_acl) and _Gemini.validator_on_off_status(anti_dos) and _Gemini.validator_on_off_status(is_predict_header) and max_requests_per_minute.isdigit():
                            allow_update_config = True
                        else:
                            allow_update_config = False

                        current_is_use_gwvd = _Gemini.get_gemini_config().is_use_g_wvd_serve
                        if current_is_use_gwvd == 0:
                            if is_use_gwvd == 1:
                                if _Gemini.validator_sensitive_value(sensitive_value) and _Gemini.validator_g_wvd_serve(decoded_g_wvd_serve, g_serve_key):
                                    allow_update_config = True
                                    _Gemini.update_gemini_config({
                                        "g_serve_key": g_serve_key,
                                    })
                                else:
                                    allow_update_config = False

                        if allow_update_config:
                            _Gemini.update_gemini_config({
                                "anti_dos": int(anti_dos),
                                "max_requests_per_minute": int(max_requests_per_minute),
                                "enable_acl": int(enable_acl),
                                "is_use_g_wvd_serve": is_use_gwvd,
                                "global_protect_mode": protect_mode,
                                "g_wvd_serve": decoded_g_wvd_serve,
                                "sensitive_value": int(sensitive_value),
                                "max_content_length": int(max_content_length) * 1024 * 1024,
                                "http_method_allow": json.dumps(http_method),
                                "safe_redirect": int(safe_redirect),
                                "protect_response": int(protect_response),
                                "trust_domain": json.dumps(trust_domain_list),
                                "is_predict_header": int(is_predict_header),
                                "socket_io": socket_io
                            })
                            flash('Configuration update successful',
                                  'config_update_success')
                        else:
                            flash('Configuration update failed',
                                  'config_update_fail')
                        return redirect(url_for('nested_service.gemini_configurate'))
                    else:
                        gemini_config = _Gemini.get_gemini_config()
                        trust_domain_list = ast.literal_eval(
                            gemini_config.trust_domain)
                        gemini_user = _Gemini.get_gemini_user()

                        return render_template('gemini-protector-gui/home/config.html',
                                               _username=gemini_user.username,
                                               _protect_mode=gemini_config.global_protect_mode,
                                               _sensitive_value=gemini_config.sensitive_value,
                                               _server_name=gemini_config.server_name,
                                               _max_content_length=int(
                                                   gemini_config.max_content_length / 1024 / 1024),
                                               _http_method=gemini_config.http_method_allow,
                                               _safe_redirect_status=gemini_config.safe_redirect,
                                               _trust_domain_list=", ".join(
                                                   trust_domain_list),
                                               _g_wvd_serve=gemini_config.g_wvd_serve,
                                               #    _g_serve_key = gemini_config.g_serve_key,
                                               _protect_response=gemini_config.protect_response,
                                               _is_enable_acl=gemini_config.enable_acl,
                                               _is_anti_dos=gemini_config.anti_dos,
                                               _is_predict_header=gemini_config.is_predict_header,
                                               _max_request_per_min=gemini_config.max_requests_per_minute,
                                               _socketio=gemini_config.socket_io,
                                               _is_use_g_wvd_serve=gemini_config.is_use_g_wvd_serve
                                               )
                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_configurate', e))

            @nested_service.route('/access-control-list', methods=['GET', 'POST'])
            def gemini_access_control_list():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    if request.method == 'POST':
                        ip_address = request.form['ip_address']
                        access_type = request.form['access_type']
                        description = request.form['description']

                        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
                        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'

                        if re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address):
                            ip = ipaddress.ip_address(ip_address)
                            if ip:
                                _Gemini.store_gemini_acl(
                                    _ipaddress=ip_address, _isallow=access_type, _desciption=description)
                                flash('ACL add successful', 'acl_success')
                            else:
                                flash('ACL add failed', 'acl_fail')
                        else:
                            flash('ACL add failed', 'acl_fail')

                        return redirect(url_for('nested_service.gemini_access_control_list'))

                    else:
                        gemini_user = _Gemini.get_gemini_user()
                        gemini_config = _Gemini.get_gemini_config()
                        is_enable_acl = gemini_config.enable_acl
                        access_control_list = _Gemini.get_gemini_acl()
                        sorted_access_control_list_data = sorted(
                            access_control_list, key=lambda x: x.created_at)

                        page = int(request.args.get('page', 1))
                        per_page = 5

                        total_records = len(sorted_access_control_list_data)
                        total_pages = (total_records +
                                       per_page - 1) // per_page

                        start_index = (page - 1) * per_page
                        end_index = start_index + per_page
                        limited_access_control_list = sorted_access_control_list_data[
                            start_index:end_index]

                        return render_template('gemini-protector-gui/home/acl.html',
                                               _username=gemini_user.username,
                                               _is_enable_acl=is_enable_acl,
                                               _gemini_acl=limited_access_control_list,
                                               _current_page=page,
                                               _total_pages=total_pages
                                               )

                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_access_control_list', e))

            @nested_service.route('/remove-acl', methods=['POST'])
            def gemini_remove_acl():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    ip_address = request.form['ip_address']

                    try:
                        ip = ipaddress.ip_address(ip_address)
                    except ValueError:
                        flash('AC remove failed. IP address {} is not valid'.format(
                            ip_address), 'acl_fail')
                        return redirect(url_for('nested_service.gemini_access_control_list'))

                    _Gemini.remove_gemini_acl(str(ip))
                    flash('AC remove successful', 'acl_success')
                    return redirect(url_for('nested_service.gemini_access_control_list'))

                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_remove_acl', e))

            @nested_service.route('/dependency-vulnerability', methods=['GET', 'POST'])
            def gemini_dependency_audit():
                try:
                    if not session.get('gemini_logged_in'):
                        return redirect(url_for('nested_service.gemini_login'))

                    if request.method == 'POST':
                        file_path = request.form['dependency_path']
                        filename = os.path.basename(file_path)
                        if filename == 'requirements.txt':
                            _Gemini.__audit_dependency_vulnerability__(
                                file_path)
                            flash('Check dependency successful', 'audit_success')
                        else:
                            flash('Check dependency failed', 'audit_fail')
                    else:
                        gemini_user = _Gemini.get_gemini_user()
                        dependency_file = _Gemini.get_dependency_file()
                        dependency_result = _Gemini.get_gemini_audit_dependency()
                        sorted_dependency_result = sorted(
                            dependency_result, key=lambda x: x.created_at)

                        page = int(request.args.get('page', 1))
                        per_page = 5

                        total_records = len(sorted_dependency_result)
                        total_pages = (total_records +
                                       per_page - 1) // per_page

                        start_index = (page - 1) * per_page
                        end_index = start_index + per_page
                        limited_dependency_result = sorted_dependency_result[start_index:end_index]

                        return render_template('gemini-protector-gui/home/dependency.html',
                                               _username=gemini_user.username,
                                               _gemini_dependency_file=dependency_file,
                                               _gemini_dependency_result=limited_dependency_result,
                                               gemini_page_pagination=len(
                                                   dependency_result),
                                               _current_page=page,
                                               _total_pages=total_pages)

                    return redirect(url_for('nested_service.gemini_dependency_audit'))

                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_dependency_audit', e))

            @nested_service.route('/event', methods=['POST'])
            def gemini_get_event():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    event_id = request.json['event_id']

                    record = _Gemini.get_gemini_detail_request_log(event_id)
                    if record:
                        if record.score is None:
                            _Gemini.update_gemini_request_log(record.event_id)
                        return jsonify({
                            "status": True,
                            "time": record.time,
                            "ip_address": record.ipaddress,
                            "event_id": record.event_id,
                            "url": record.url,
                            "user_agent": record.useragent,
                            "request":  record.request,
                            "req_body": record.req_body,
                            "response": record.response,
                            "res_content": str(record.res_content),
                            "attack_type": record.attack_type,
                            "score": record.score,
                            "hash": record.hash,
                            "latitude": record.latitude,
                            "longitude": record.longitude,
                            "created_at": record.created_at,
                            "updated_at": record.updated_at
                        })
                    else:
                        return jsonify({
                            "status": False,
                            "message": "Event ID does not exist"
                        })
                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_get_event', e))

            @nested_service.route('/event-feedback', methods=['POST'])
            def gemini_event_feedback():
                try:
                    if not session.get('gemini_logged_in'):
                        return redirect(url_for('nested_service.gemini_login'))

                    event_id = request.json['event_id']
                    feedback_value = request.json['feedback_value']

                    record = _Gemini.get_gemini_detail_request_log(event_id)
                    if record:
                        sentence = "{}{}".format(
                            record.request, record.req_body)
                        _Gemini.store_gemini_feedback(
                            sentence, int(feedback_value))
                        _Gemini.update_gemini_request_log(record.event_id)
                        return jsonify({
                            "status": True,
                            "message": "Update feedback successful"
                        })
                    else:
                        return jsonify({
                            "status": False,
                            "message": "Update feedback failed"
                        })
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_event_feedback', e))

            @nested_service.route('/endpoint', methods=['GET'])
            def gemini_endpoint():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        return redirect(url_for('nested_service.gemini_login'))

                    app_path = _Gemini.get_gemini_config().app_path
                    links = []
                    for rule in flask_app.url_map.iter_rules():
                        options = {}
                        for arg in rule.arguments:
                            options[arg] = "[{0}]".format(arg)

                        methods = ','.join(rule.methods)
                        url = url_for(rule.endpoint, _external=True, **options)
                        if app_path not in url:
                            link = {
                                'endpoint': rule.endpoint,
                                'method': methods,
                                'url': url,
                            }
                            links.append(link)

                    _sorted_links = sorted(links, key=lambda x: x['endpoint'])
                    page = int(request.args.get('page', 1))
                    per_page = 5

                    total_records = len(_sorted_links)
                    total_pages = (total_records + per_page - 1) // per_page

                    start_index = (page - 1) * per_page
                    end_index = start_index + per_page
                    limited_links = _sorted_links[start_index:end_index]
                    return render_template('gemini-protector-gui/home/endpoint.html',
                                           _sorted_links=limited_links,
                                           _current_page=page,
                                           _total_pages=total_pages
                                           )
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_endpoint', e))

            @nested_service.route('/feedback', methods=['GET'])
            def gemini_feedback():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        return redirect(url_for('nested_service.gemini_login'))

                    feedback = _Gemini.get_gemini_feedback()

                    _sorted_links = sorted(
                        feedback, key=lambda x: x.created_at)
                    page = int(request.args.get('page', 1))
                    per_page = 5

                    total_records = len(_sorted_links)
                    total_pages = (total_records + per_page - 1) // per_page

                    start_index = (page - 1) * per_page
                    end_index = start_index + per_page
                    limited_links = _sorted_links[start_index:end_index]
                    return render_template('gemini-protector-gui/home/feedback.html',
                                           _sorted_links=limited_links,
                                           _current_page=page,
                                           _total_pages=total_pages
                                           )
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_endpoint', e))

            @nested_service.route('/export-feedback')
            def gemini_export_feedback():
                try:
                    is_install = _Gemini.get_gemini_config().is_install
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        return redirect(url_for('nested_service.gemini_login'))

                    csv_file = _Gemini.export_gemini_feedback()
                    return send_file(csv_file, as_attachment=True)
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_export_feedback', e))

            @nested_service.route('/logout')
            def gemini_logout():
                try:
                    app_username = _Gemini.get_gemini_user().username
                    session['gemini_logged_in'] = False
                    flash('Goodbye {}!'.format(app_username), 'logout')
                    return redirect(url_for('nested_service.gemini_login'))
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('nested_service.route.gemini_logout', e))

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

    def handler_g_wvd_serve_health():
        try:
            if _Gemini.g_wvd_serve_health(_self_context=True):
                logger.info(
                    "[+] Connected to G-WVD")
            else:
                logger.error(
                    "[x_x] Cannot connect to G-WVD")
                while True:
                    try:
                        diagnostic = input(
                            "[?] Do you run diagnostic (y/N): ") or "y"
                    except Exception as e:
                        logger.error(
                            "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_GUI.handler_g_wvd_serve_health', e))
                        continue
                    else:
                        break
                if diagnostic == 'y' or diagnostic == 'Y':
                    code = _Gemini.g_serve_diagnostic()
                    if code == 200:
                        logger.info(
                            "[+] Connected to G-WVD")
                    elif code == 400:
                        logger.info(
                            "[!] Please check error log on G-WVD")
                        sys.exit()
                    elif code == 401:
                        logger.info(
                            "[!] Please check your G-WVD key")
                        sys.exit()
                    elif code == 500:
                        logger.info(
                            "[!] Please check error log on G-WVD")
                        sys.exit()
                    else:
                        while True:
                            try:
                                answer = input("[?] Do you want continue without G-WVD (y/N): ") or "y"
                            except Exception as e:
                                logger.error(
                                    "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_GUI.handler_g_wvd_serve_health', e))  
                                continue 
                            else:
                                break
                        if answer == 'N' or answer == 'n':
                            sys.exit()
                else:
                    while True:
                        try:
                            answer = input(
                                "[?] Do you want continue (y/N): ") or "y"
                        except Exception as e:
                            logger.error(
                                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_GUI.handler_g_wvd_serve_health', e))
                            continue
                        else:
                            break
                    if answer == 'N' or answer == 'n':
                        sys.exit()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_GUI.handler_g_wvd_serve_health', e))
