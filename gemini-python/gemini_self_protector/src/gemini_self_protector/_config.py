import os
import yaml
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ._logger import logger
import json
from ipaddress import ip_address
from datetime import datetime
from ._model import Base, tb_User, tb_Config, tb_Tracking, tb_Analysis, tb_AccessControlList


class _Config(object):

    def __init__(self, working_directory):

        database_file = working_directory+'/gemini.db'
        try:
            engine = create_engine('sqlite:///'+database_file)
            Base.metadata.create_all(engine)
            Session = sessionmaker(bind=engine)
            session = Session()

            user = tb_User(
                name='superadmin', password=''
            )
            config = tb_Config(
                isinstall=False,
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
                server_name='gemini',
                safe_redirect=False,
                safe_response=False,
                notification_channel=False
            )
            tracking = tb_Tracking(
                abnormal_request=0,
                normal_request=0,
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
            instance = session.query(model).first()
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

    def get_tb_tracking() -> None:
        try:
            session = _Config.get_session()
            tracking = _Config.get_model_instance_first(session, tb_Tracking)
            return tracking
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.get_tb_tracking', e))

    def update_tb_tracking(update_content):
        try:
            session = _Config.get_session()
            _Config.update_model_instance(session, tb_Tracking, update_content)
        except Exception as e:
            logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                '_Config.update_tb_tracking', e))

    def get_tb_analysis() -> None:
        try:
            session = _Config.get_session()
            analysis = _Config.get_model_instance_first(session, tb_Analysis)
            return analysis
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.get_tb_analysis', e))

    def store_tb_analysis(ipaddress, request, attack_type, predict, incident_id):
        try:
            session = _Config.get_session()
            new_analysis = tb_Analysis(
                ipaddress=ipaddress,
                request=request,
                attack_type=attack_type,
                predict=predict,
                incident_id=incident_id,
                status='active',
                review=False
            )
            session.add(new_analysis)
            session.commit()
            session.close()
        except Exception as e:
            logger.error("[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                '_Config.store_tb_analysis', e))

    def get_tb_acl() -> None:
        try:
            session = _Config.get_session()
            acl = _Config.get_model_instance_all(session, tb_AccessControlList)
            return acl
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong, please check your error message.\n Message - {0}".format('_Config.get_tb_acl', e))

    def update_acl(_dict) -> None:

        try:
            acl_path = _Config.get_tb_config('gemini_acl_path')
            with open(acl_path, "r") as f:
                existing_data = json.load(f)

            existing_ips = [item["Ip"] for item in existing_data["gemini_acl"]]

            if _dict["Ip"] in existing_ips:
                return False
            else:
                existing_data["gemini_acl"].append(_dict)
                # Write the add new data back to the file
                with open(acl_path, "w") as f:
                    json.dump(existing_data, f, indent=4)
                return True
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.update_acl', e))

    def check_acl(_ip_address) -> None:
        try:
            session = _Config.get_session()
            acl_record = session.query(tb_AccessControlList).filter_by(
                ipaddress=_ip_address).first()
            session.close()
            if acl_record:
                return True
            else:
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.check_acl', e))

    def remove_acl(_ip_address):
        """
        It opens a json file, reads the contents, removes an object from the json file, and then writes
        the contents back to the file

        :param _ip_address: The IP address to be removed from the ACL
        """
        try:
            acl_path = _Config.get_tb_config('gemini_acl_path')
            with open(acl_path, "r") as f:
                acl_data = json.load(f)

            for acl in acl_data["gemini_acl"]:
                if acl.get("Ip") == _ip_address:
                    acl_data["gemini_acl"].remove(acl)
            with open(acl_path, "w") as f:
                json.dump(acl_data, f, indent=4)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.remove_acl', e))

    def init_audit_dependency(working_directory):
        """
        This function creates an empty json file called audit_dependency.json in the working directory

        :param working_directory: The directory where the audit_dependency.json file is located
        """
        data_file = working_directory+'/audit-dependency.json'
        try:
            # create an empty dictionary
            data = {"gemini_audit_dependency": []}

            # Write the empty dictionary to the new file
            with open(data_file, "w") as f:
                # use pickle to dump the dictionary to the file
                json.dump(data, f,  indent=4)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.init_audit_dependency', e))

    def update_audit_dependency(_dict):
        """
        It takes a dictionary as an argument, and appends it to a JSON file

        :param _dict: This is the dictionary that you want to add to the json file
        """
        try:
            audit_dependency_path = _Config.get_tb_config(
                'gemini_audit_dependency')
            now = datetime.now()
            current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            with open(audit_dependency_path, "r") as f:
                existing_data = json.load(f)

            existing_data["gemini_audit_dependency"].append(
                {str(current_time): _dict})
            # Write the add new data back to the file
            with open(audit_dependency_path, "w") as f:
                json.dump(existing_data, f, indent=4)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.update_audit_dependency', e))
