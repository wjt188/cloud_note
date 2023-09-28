import hashlib


# 加密密码，生成hash值
def generate_hash(password):
    m = hashlib.md5()
    m.update(password.encode())
    return m.hexdigest()
#
# def decode_hash(hash_value):
#