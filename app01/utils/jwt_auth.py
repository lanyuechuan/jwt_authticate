import jwt
import datetime
from DWTDemo import settings

def create_token(payload,timeout=1):

    SALT = settings.SECRET_KEY

    # 构造header
    headers = {
        'typ': 'jwt',
        'alg': 'HS256'
    }
    # 构造payload
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=timeout)  # 超时时间自定义
    token = jwt.encode(payload=payload, key=SALT, algorithm="HS256", headers=headers).decode('utf-8')
    return token
