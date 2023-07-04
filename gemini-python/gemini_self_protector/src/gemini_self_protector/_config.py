import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ._logger import logger
import json
import csv
from ipaddress import ip_address
from datetime import datetime
from ._model import Base, tb_User, tb_Config, tb_Summary, tb_RequestLog, tb_AccessControlList, tb_Dependency, tb_Feedback

class _Config(object):

    def __init__(self, working_directory):

        database_file = working_directory+'/gemini.db'
        try:
            engine = create_engine('sqlite:///'+database_file)
            Base.metadata.create_all(engine)
            Session = sessionmaker(bind=engine)
            session = Session()

            user = tb_User(
                username='superadmin', password=''
            )
            config = tb_Config(
                isinstall=0,
                working_directory=working_directory,
                database_path=database_file,
                secret_key=str(os.urandom(24)),
                global_protect_mode='monitor',
                max_content_length=52428800,
                sensitive_value=50,
                http_method_allow=json.dumps(
                    ['OPTIONS', 'GET', 'POST', 'PUT', 'DELETE']),
                cors={'origin': '*', 'methods': '*',
                      'credentials': True, 'headers': ['Content-Type']},
                trust_domain= json.dumps(['localhost.dev']),
                server_name='gemini',
                safe_redirect=0,
                protect_response=0,
                notification_channel=0,
                enable_acl=0,
                anti_dos=1,
                max_requests_per_minute=100,
            )
            tracking = tb_Summary(
                abnormal_request=0,
                normal_request=0,
                abnormal_response=0,
                normal_response=0,
                total_request=0
            )
            session.add(user)
            session.add(config)
            session.add(tracking)
            session.commit()
            session.close()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.__init__', e))

    def get_session():
        try:
            running_directory = os.getcwd()
            gemini_working_directory = os.path.join(
                running_directory, r'gemini-protector')
            engine = create_engine(
                'sqlite:///'+gemini_working_directory+'/gemini.db')
            Session = sessionmaker(bind=engine)
            session = Session()
            return session
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.get_session', e))

    def get_model_instance_first(session, model):
        try:
            instance = session.query(model).filter_by(id=1).first()
            session.close()
            return instance
        except Exception as e:
            logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                '_Config.get_model_instance_first', e))

    def get_model_instance_all(session, model):
        try:
            instance = session.query(model).all()
            session.close()
            return instance
        except Exception as e:
            logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                '_Config.get_model_instance_all', e))

    def update_model_instance(session, model, update_content):
        try:
            instance = session.query(model).first()
            for column_name, new_value in update_content.items():
                setattr(instance, column_name, new_value)
            session.commit()
            session.close()
        except Exception as e:
            logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                '_Config.update_model_instance', e))

    def get_tb_config() -> None:
        try:
            session = _Config.get_session()
            config = _Config.get_model_instance_first(session, tb_Config)
            return config
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.get_tb_config', e))

    def update_tb_config(update_content):
        try:
            session = _Config.get_session()
            _Config.update_model_instance(session, tb_Config, update_content)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.update_tb_config', e))

    def get_tb_summary() -> None:
        try:
            session = _Config.get_session()
            tracking = _Config.get_model_instance_first(session, tb_Summary)
            return tracking
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.get_tb_summary', e))

    def update_tb_summary(update_content):
        try:
            session = _Config.get_session()
            _Config.update_model_instance(session, tb_Summary, update_content)
        except Exception as e:
            logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                '_Config.update_tb_summary', e))

    def get_tb_request_log() -> None:
        try:
            session = _Config.get_session()
            analysis = _Config.get_model_instance_all(session, tb_RequestLog)
            return analysis
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.get_tb_request_log', e))

    def store_tb_request_log(ipaddress, url, request, req_body, response, res_content, useragent, attack_type, predict, event_id, latitude, longitude):
        try:
            session = _Config.get_session()
            new_record = tb_RequestLog(
                ipaddress=ipaddress,
                url=url,
                request=request,
                req_body=req_body,
                response=response,
                res_content=res_content,
                useragent=useragent,
                attack_type=attack_type,
                predict=predict,
                event_id=event_id,
                latitude=latitude,
                longitude=longitude,
                status='active',
                review=False
            )
            session.add(new_record)
            session.commit()
            session.close()
        except Exception as e:
            logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                '_Config.store_tb_request_log', e))

    def get_tb_request_log_first(event_id) -> None:
        try:
            session = _Config.get_session()
            req_record = session.query(tb_RequestLog).filter_by(
                event_id=event_id).first()
            session.close()
            return req_record
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.get_tb_config', e))

    def update_record_request_log(_event_id) -> None:
        try:
            session = _Config.get_session()
            request_log_record = session.query(tb_RequestLog).filter_by(
                event_id=_event_id).first()
            if request_log_record:
                request_log_record.review = True
                session.commit()
                session.close()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.update_record_request_log', e))

    def get_tb_acl() -> None:
        try:
            session = _Config.get_session()
            acl = _Config.get_model_instance_all(session, tb_AccessControlList)
            return acl
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong, please check your error message.\n Message - {0}".format('_Config.get_tb_acl', e))

    def store_tb_acl(ipaddress, isallow, desciption):
        try:
            session = _Config.get_session()
            new_acl = tb_AccessControlList(
                ipaddress=ipaddress,
                is_allowed=isallow,
                desciption=desciption
            )
            session.add(new_acl)
            session.commit()
            session.close()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.store_tb_acl', e))

    def check_acl(_ip_address) -> None:
        try:
            session = _Config.get_session()
            acl_record = session.query(tb_AccessControlList).filter_by(
                ipaddress=_ip_address).first()
            session.close()
            if acl_record and acl_record.is_allowed == 0:
                return True
            else:
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.check_acl', e))

    def remove_record_acl(_ip_address):
        """
        It opens a json file, reads the contents, removes an object from the json file, and then writes
        the contents back to the file

        :param _ip_address: The IP address to be removed from the ACL
        """
        try:
            session = _Config.get_session()
            acl_record = session.query(tb_AccessControlList).filter_by(
                ipaddress=_ip_address).first()
            if acl_record:
                session.delete(acl_record)
                session.commit()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.remove_acl', e))

    def get_tb_user() -> None:
        try:
            session = _Config.get_session()
            user = _Config.get_model_instance_first(session, tb_User)
            return user
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.get_tb_user', e))

    def update_tb_user(update_content):
        try:
            session = _Config.get_session()
            _Config.update_model_instance(session, tb_User, update_content)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.update_tb_user', e))

    def get_tb_dependency() -> None:
        try:
            session = _Config.get_session()
            dependency = _Config.get_model_instance_all(session, tb_Dependency)
            return dependency
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong, please check your error message.\n Message - {0}".format('_Config.get_tb_dependency', e))

    def store_tb_dependency(package, version, cve_id, severity):
        try:
            session = _Config.get_session()
            new_record = tb_Dependency(
                package=package,
                version=version,
                cve_id=cve_id,
                severity=severity
            )
            session.add(new_record)
            session.commit()
            session.close()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.store_tb_dependency', e))

    def get_tb_feedback() -> None:
        try:
            session = _Config.get_session()
            feedback = _Config.get_model_instance_all(session, tb_Feedback)
            return feedback
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong, please check your error message.\n Message - {0}".format('_Config.get_tb_dependency', e))

    def store_tb_feedback(_sentence, _label):
        try:
            session = _Config.get_session()
            new_record = tb_Feedback(
                sentence=_sentence,
                label=_label,
            )
            session.add(new_record)
            session.commit()
            session.close()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.store_gemini_feedback', e))

    def export_tb_feedback() -> str:
        try:
            session = _Config.get_session()
            feedback = _Config.get_model_instance_all(session, tb_Feedback)

            gemini_working_directory = _Config.get_tb_config().working_directory
            csv_file_path = gemini_working_directory+"/feedback.csv"

            with open(csv_file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Sentence', 'Label'])  # Write header
                for row in feedback:
                    writer.writerow([row.sentence, row.label])

            return csv_file_path
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format('_Config.export_tb_feedback', e))