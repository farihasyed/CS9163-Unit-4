import re
import os

file = open("secrets.txt")
lines = file.readlines()
key_values = [re.split('[=](?!\n)', line) for line in lines]
for pair in key_values:
    key = pair[0].strip()
    value = pair[1].strip()
    os.environ[key] = value
    print("export {key}={value}".format(key=key, value=value))

print(os.environ['ADMIN_USERNAME'], os.environ['ADMIN_PASSWORD'], os.environ['ADMIN_PHONE'])
print(os.environ['KEY'], os.environ['FLASK_KEY'])
print(os.environ['DATABASE_PATH'])
