import subprocess 
 
command = input("Enter a command: ") 
 
subprocess.run(command, shell=True) 
