import bcrypt
import jwt
from datetime import datetime, timedelta

def hash_password(plain_password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    hashed_password = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def is_password_correct(plain_password: str, hashed_password: str) -> bool:
    try:
        is_password_correct = bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.strip().encode('utf-8'))
    except:
        return False
    
    return is_password_correct

def generate_jwt(email: str) -> str:
    payload = {
        'sub': email,
        'exp': datetime.utcnow() + timedelta(minutes=1)
    }
    token = jwt.encode(payload, 'my-shared-secret', algorithm='HS256')
    return token

def is_jwt_valid(token: str) -> bool:
    try:
        decoded_payload = jwt.decode(token, 'my-shared-secret', algorithms=['HS256'])
    except:
        return False
    
    if decoded_payload.get('exp') < datetime.utcnow().timestamp():
        return False
    
    return True