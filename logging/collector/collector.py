import json
import sys
import urllib.request

LOGSTASH_URL = "http://localhost:8080"

def send_event(event):
	data = json.dumps(event).encode("utf-8")

	request = urllib.request.Request(
	LOGSTASH_URL,
	data=data,
	headers={"Content-type": "application/json"},
	method =  "POST" )

	with urllib.request.urlopen(request) as response :
		print("Logstash:" , response.status)

def main():

	if len(sys.argv) != 2 :
		print("Usage: python python3 collector.py report.json")
		sys.exit(1)

	filename = sys.argv[1]

	with open(filename, "r" , encoding="utf-8") as file :
		data = json.load(file)

		if isinstance(data, list) :
			for event in data :
				event["source_type"] = "security_scan"
				send_event(event)
		else :
			data["source_type"] = "security_scan"
			send_event(data)
if __name__ ==  "__main__" :
	main()
