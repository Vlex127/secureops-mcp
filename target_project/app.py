import os
import subprocess
import pickle
import yaml

AWS_SECRET = "AIZAabc123XYZsecretKeyExample"
user_input = input("Enter domain: ")
os.system(f"ping {user_input}")

exec(user_input)

result = subprocess.Popen(["ls", "-la"], shell=True)

data = pickle.loads(b"malicious")
yaml.load(data)
