from flask import Flask, Blueprint, request, make_response, render_template, session, redirect, url_for, flash, stream_with_context, jsonify, send_file
from ._logger import logger
from ._gemini import _Gemini
from passlib.hash import argon2
from datetime import datetime, timezone
import ipaddress
import re
import os
import json
import ast
from math import floor


class _Gemini_GUI(object):

    def __init__(self, flask_app: Flask) -> None:
        logger.info(
            "[+] Running gemini-self protector - GUI Mode")

        # @flask_app.before_request
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
                    isInstall = _Gemini.get_gemini_config().isinstall
                    if int(isInstall):
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
                    isInstall = _Gemini.get_gemini_config().isinstall
                    if int(isInstall):
                        return redirect(url_for('nested_service.gemini_dashboard'))
                    else:
                        if request.method == 'POST':
                            protect_mode = request.form['radio-mode']
                            sensitive_value = request.form['sensitive-value']
                            app_path = request.form['gemini-app-path']
                            password = request.form['pwd']
                            confirm_password = request.form['cpwd']
                            notification_channel = request.form['radio-channel']
                            predict_server_key_auth = request.form['key-auth-server-value']
                            predict_server = request.form['predit-server-value']
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

                            if _Gemini.validator_protect_mode(protect_mode) and _Gemini.validator_sensitive_value(sensitive_value) and _Gemini.validator_app_path(app_path) and _Gemini.validator_dashboard_password(password, confirm_password) and _Gemini.validator_notification_channel(notification_channel) and _Gemini.validator_predict_server(predict_server, predict_server_key_auth):
                                _Gemini.update_gemini_config({
                                    "isinstall": True,
                                    "global_protect_mode": protect_mode,
                                    "sensitive_value": int(sensitive_value),
                                    "app_path": app_path,
                                    "notification_channel": notification_channel,
                                    "telegram_token": telegram_token,
                                    "telegram_chat_id": telegram_chat_id,
                                    "notification_webhook": notification_webhook,
                                    "predict_server": predict_server,
                                    "predict_server_key_auth": predict_server_key_auth
                                })
                                _Gemini.update_gemini_user({
                                    "password": argon2.hash(password),
                                })
                                logger.info(
                                    "[+] Install gemini-self-protector successful.!")
                                flash(
                                    'Instal gemini-self-protector successful. Login and explore now', 'login')
                                return redirect(url_for('nested_service.gemini_login'))
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
                    is_install = _Gemini.get_gemini_config().isinstall
                    if int(is_install) == 0:
                        return redirect(url_for('nested_service.gemini_install'))

                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    if request.method == 'POST':
                        key = request.form['key']
                        if _Gemini.validator_key_auth(key):
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
                    is_install = _Gemini.get_gemini_config().isinstall
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

                        password_check = argon2.verify(password, app_password)

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
                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    if request.method == 'POST':
                        password = request.form['pwd']
                        confirm_password = request.form['cpwd']

                        if not _Gemini.validator_dashboard_password(password, confirm_password):
                            return render_template('gemini-protector-gui/home/profile.html', msg="Invalid password")

                        _Gemini.update_gemini_config({
                            "gemini_app_password": argon2.hash(password),
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
                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    gemini_summary = _Gemini.get_gemini_summary()
                    gemini_config = _Gemini.get_gemini_config()
                    gemini_user = _Gemini.get_gemini_user()
                    request_log = _Gemini.get_gemini_request_log()
                    # predict_server_status = _Gemini.health_check_predict_server()

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
                        'DOS': 0
                    }

                    for log in request_log:
                        attack_type = log.attack_type
                        if attack_type in attack_counts:
                            attack_counts[attack_type] += 1

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
                                           _gemini_attack_counts=attack_counts
                                           )
                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_dashboard', e))

            @nested_service.route('/configurate', methods=['GET', 'POST'])
            def gemini_configurate():
                try:
                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    if request.method == 'POST':
                        predict_server = request.form['predict_server']
                        protect_mode = request.form['protect_mode']
                        sensitive_value = request.form['sensitive_value']
                        max_content_length = request.form['max_content_length']
                        http_method = request.form.getlist('http_method[]')
                        safe_redirect_status = request.form['safe_redirect_status']
                        trust_domain_list = [d.strip() for d in request.form.get(
                            'trust_domain_list').split(',')]
                        protect_response_status = request.form['protect_response_status']
                        acl_status = request.form['acl_status']
                        anti_dos = request.form['anti_dos_status']
                        max_request_per_min = request.form['max_request_per_min']

                        if _Gemini.validator_protect_mode(protect_mode) and _Gemini.validator_sensitive_value(sensitive_value) and max_content_length.isdigit() and _Gemini.validator_http_method(http_method) and _Gemini.validator_on_off_status(safe_redirect_status) and _Gemini.validator_trust_domain(trust_domain_list) and _Gemini.validator_on_off_status(protect_response_status) and _Gemini.validator_on_off_status(acl_status) and _Gemini.validator_on_off_status(anti_dos) and max_request_per_min.isdigit():

                            _Gemini.update_gemini_config({
                                "predict_server": predict_server,
                                "global_protect_mode": protect_mode,
                                "sensitive_value": int(sensitive_value),
                                "max_content_length": int(max_content_length) * 1024 * 1024,
                                "http_method_allow": json.dumps(http_method),
                                "safe_redirect": int(safe_redirect_status),
                                "protect_response": int(protect_response_status),
                                "trust_domain": json.dumps(trust_domain_list),
                                "enable_acl": int(acl_status),
                                "anti_dos": int(anti_dos),
                                "max_requests_per_minute": int(max_request_per_min)
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
                                               _predict_server=gemini_config.predict_server,
                                               _protect_response=gemini_config.protect_response,
                                               _is_enable_acl=gemini_config.enable_acl,
                                               _is_anti_dos=gemini_config.anti_dos,
                                               _max_request_per_min=gemini_config.max_requests_per_minute
                                               )
                except Exception as e:
                    logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                        'nested_service.route.gemini_configurate', e))

            @nested_service.route('/access-control-list', methods=['GET', 'POST'])
            def gemini_access_control_list():
                try:
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
                                    ipaddress=ip_address, isallow=access_type, desciption=description)
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
                    if not session.get('gemini_logged_in'):
                        flash('Please login', 'required_login')
                        return redirect(url_for('nested_service.gemini_login'))

                    event_id = request.json['event_id']

                    record = _Gemini.get_gemini_detail_request_log(event_id)
                    if record:
                        if record.predict is None:
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
                            "predict": record.predict,
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
