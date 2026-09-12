import subprocess

command = input("Enter command")

subprocess.Popen("ls %s" % command , shell=True)
