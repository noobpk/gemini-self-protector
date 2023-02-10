import os
import yaml
from ._gemini import _Gemini
from functools import wraps
from flask import Flask, request, make_response, render_template, session, redirect, url_for, flash
from ._logger import logger

class GeminiManager(object):

    def __init__(self, flask_app: Flask = None, license_key="w", protect_mode="w", sensitive_value="w"):
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
            init_config_content = {
                'gemini-self-protector': {
                    'gemini_working_directory': gemini_working_directory,
                    'gemini_secret_key': str(os.urandom(24)),
                    'gemini_dashboard_path': None,
                    'gemini_config_path': gemini_working_directory+'/config.yml',
                    'gemini_log_path': gemini_working_directory+'/log',
                    'gemini_normal_request': 0,
                    'gemini_abnormal_request': 0,
                }
            }
            _Gemini.init_config(gemini_working_directory, init_config_content)
            _Gemini.verify_license_key(license_key)

        _Gemini.update_config({
            "gemini_global_protect_mode":_Gemini.verify_protect_mode(protect_mode),
            "gemini_sensitive_value": _Gemini.verify_sensitive_value(sensitive_value)
            })   

        # Register this extension with the flask app now (if it is provided)
        if flask_app is not None:
            self.init_flask_app(flask_app)

    def init_flask_app(self, flask_app: Flask) -> None:
        if flask_app.secret_key is None:
            flask_app.secret_key = _Gemini.get_config('gemini_secret_key')
    
        if flask_app.template_folder and flask_app.static_folder:
            if _Gemini.get_config('gemini_dashboard_path') is None:
                _Gemini.init_gemini_dashboard_path()
                _Gemini.init_gemini_dashboard_password()

            _Gemini.init_gemini_dashboard(flask_app.template_folder, flask_app.static_folder)
            dashboard_path = _Gemini.get_config('gemini_dashboard_path')
            logger.info("[+] Access Your Gemini Dashboard as Path: http://host:port/{}/dashboard".format(dashboard_path))
            logger.info("[+] Check the config file at gemini_protector/config.yml/config.yaml for the password.")
            
            @flask_app.route('/'+dashboard_path+'/login', methods=['GET', 'POST'])
            def gemini_login():
                if request.method == 'GET' and session.get('gemini_logged_in'):
                    return redirect(url_for('gemini_dashboard'))
                elif request.method == 'POST':
                    error = None
                    password = request.form['password']
                    secret_password = _Gemini.get_config('gemini_dashboard_password')
                    if password == secret_password:
                        logger.info("[+] Login sucessfully.!")
                        session['gemini_logged_in'] = True
                        return redirect(url_for('gemini_dashboard'))
                    else:
                        return render_template('gemini_protector_template/login.html', error="Incorrect Password")
                else:
                    return render_template('gemini_protector_template/login.html')

            @flask_app.route('/'+dashboard_path+'/dashboard')
            def gemini_dashboard():
                if session.get('gemini_logged_in'):
                    normal_request = _Gemini.get_config('gemini_normal_request')
                    abnormal_request = _Gemini.get_config('gemini_abnormal_request')
                    sensitive_value = _Gemini.get_config('gemini_sensitive_value')
                    global_protect_mode = _Gemini.get_config('gemini_global_protect_mode')
                    load_data_log = _Gemini.load_gemini_log()
                    return render_template('gemini_protector_template/dashboard.html', 
                        _protect_mode=global_protect_mode,
                        _normal_request=normal_request, 
                        _abnormal_request=abnormal_request,
                        _sensitive_value=sensitive_value,
                        _gemini_log=load_data_log
                        )
                else:
                    logger.warning("[!] Unauthentication Access.!")
                    flash('Please login')
                    return redirect(url_for('gemini_login'))

            @flask_app.route('/'+dashboard_path+'/update-config', methods=['POST'])
            def gemini_update_config():
                if session.get('gemini_logged_in'):
                    protect_mode = request.form['protect_mode']
                    sensitive_value = request.form['sensitive_value']
            
                    validate_protect_mode = ['on', 'off', 'block', 'monitor']
                    if protect_mode in validate_protect_mode and 0 <= int(sensitive_value) <= 100:
                        _Gemini.update_config({
                            "gemini_global_protect_mode":_Gemini.verify_protect_mode(protect_mode),
                            "gemini_sensitive_value": _Gemini.verify_sensitive_value(sensitive_value)
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

            @flask_app.route('/'+dashboard_path+'/logout')
            def gemini_logout():
                session['gemini_logged_in'] = False
                flash('Logout successfully!')
                return redirect(url_for('gemini_login'))

    def flask_protect_extended(self, protect_mode=None):
        """
        This function is used to protect the Flask application from malicious requests
        
        :param protect_mode: This is the mode you want to use for the protection
        :return: The function is being returned.
        """
        def _gemini_self_protect(f):
            @wraps(f)
            def __gemini_self_protect(*args, **kwargs):
                global_protect_mode = _Gemini.get_config('gemini_global_protect_mode')
                if protect_mode is None:
                    gemini_protect_mode = global_protect_mode
                elif protect_mode is not None and global_protect_mode == 'off':
                    gemini_protect_mode = 'off'
                else:
                    gemini_protect_mode = protect_mode

                protect = _Gemini.__load_protect_flask__(gemini_protect_mode)
                if protect[0]:
                    response = make_response(f(*args, **kwargs))
                    response.headers['X-Gemini-Self-Protector'] = gemini_protect_mode
                    return response
                else:
                    current_time = protect[1]
                    ip_address = protect[2]
                    incedent_id = protect[3]
                    response = make_response("This request was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(current_time, ip_address, incedent_id), 200)
                    response.headers['X-Gemini-Self-Protector'] = gemini_protect_mode
                    return response
            return __gemini_self_protect
        return _gemini_self_protect

    def django_protect_extended(self):
        return True
