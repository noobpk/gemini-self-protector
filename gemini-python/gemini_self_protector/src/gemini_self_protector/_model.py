from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Boolean, func
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# Define the model


class tb_User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    name = Column(String)
    password = Column(String)


class tb_Config(Base):
    __tablename__ = 'configs'

    id = Column(Integer, primary_key=True)
    license_key = Column(String)
    isinstall = Column(Integer)
    access_token = Column(String)
    app_path = Column(String)
    database_path = Column(String)
    cors = Column(JSON)
    global_protect_mode = Column(String)
    http_method_allow = Column(String)
    max_content_length = Column(Integer)
    notification_channel = Column(String)
    notification_webhook = Column(String)
    predict_server = Column(String)
    safe_redirect = Column(String)
    safe_response = Column(String)
    secret_key = Column(String)
    sensitive_value = Column(Integer)
    server_name = Column(String)
    telegram_chat_id = Column(String)
    telegram_token = Column(String)
    trust_domain = Column(String)
    working_directory = Column(String)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class tb_Tracking(Base):
    __tablename__ = 'trackings'

    id = Column(Integer, primary_key=True)
    abnormal_request = Column(Integer)
    abnormal_response = Column(Integer)
    normal_request = Column(Integer)
    normal_response = Column(Integer)
    total_request = Column(Integer)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class tb_Analysis(Base):
    __tablename__ = 'analysis'

    id = Column(Integer, primary_key=True)
    time = Column(DateTime, default=func.now())
    ipaddress = Column(String)
    request = Column(String)
    attack_type = Column(String)
    predict = Column(Float)
    incident_id = Column(String)
    status = Column(String)
    review = Column(String)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class tb_AccessControlList(Base):
    __tablename__ = 'acls'

    id = Column(Integer, primary_key=True)
    ipaddress = Column(String, unique=True)
    is_allowed = Column(Boolean)
    desciption = Column(String)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())


class tb_Dependency(Base):
    __tablename__ = 'dependencies'

    id = Column(Integer, primary_key=True)
    package = Column(String)
    version = Column(String)
    cve_id = Column(String)
    severity = Column(String)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
