import bcrypt

# HASH PASSWORD
def hash_password(password):

    salt = bcrypt.gensalt()

    hashed = bcrypt.hashpw(
        password.encode('utf-8'),
        salt
    )

    return hashed.decode('utf-8')

# VERIFY PASSWORD
def verify_password(password, hashed_password):

    return bcrypt.checkpw(
        password.encode('utf-8'),
        hashed_password.encode('utf-8')
    )
