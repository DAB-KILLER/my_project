import json
import sys
import os
import urllib.request

LOGSTASH_URL = "http://localhost:8080"
github_metadata = { 
    "repository": os.getenv("GITHUB_REPOSITORY"), 
    "commit_sha": os.getenv("GITHUB_SHA"), 
    "branch": os.getenv("GITHUB_REF_NAME"), 
    "github_run_id": os.getenv("GITHUB_RUN_ID") } 



def normalize_bandit(event, github_metadata): 
    return { 
        "scanner": "bandit", 
        "severity": event.get("issue_severity"), 
        "rule_id": event.get("test_id"), 
        "message": event.get("issue_text"), 
        "file": event.get("filename"), 
        "line": event.get("line_number"), 
        "package": None, 
        "target": None, 
        "repository": github_metadata["repository"], 
        "commit_sha": github_metadata["commit_sha"], 
        "branch": github_metadata["branch"], 
        "github_run_id": github_metadata["github_run_id"], 
        "details": { 
            "confidence": event.get("issue_confidence"), 
            "cwe_id": event.get("issue_cwe", {}).get("id") 
        }, 
        "source_type": "security_scan" } 

def normalize_semgrep(event, github_metadata): 
    extra = event.get("extra", {}) 
    metadata = extra.get("metadata", {}) 
    return { 
        "scanner": "semgrep", 
        "severity": extra.get("severity"), 
        "rule_id": event.get("check_id"), 
        "message": extra.get("message"), 
        "file": event.get("path"), 
        "line": event.get("start", {}).get("line"), 
        "package": None, 
        "target": None, 
        "repository": github_metadata["repository"], 
        "commit_sha": github_metadata["commit_sha"], 
        "branch": github_metadata["branch"], 
        "github_run_id": github_metadata["github_run_id"], 
        "details": { 
            "cwes": metadata.get("cwe"), 
            "category": metadata.get("category"), 
            "confidence": metadata.get("confidence"), 
            "likelihood": metadata.get("likelihood"), 
            "impact": metadata.get("impact") 
        }, 
        "source_type": "security_scan" } 


def normalize_gitleaks(event, github_metadata): 
    return { 
        "scanner": "gitleaks", 
        "severity": "HIGH", 
        "rule_id": event.get("rule"), 
        "message": event.get("rule"), 
        "file": event.get("file"), 
        "line": event.get("lineNumber"), 
        "package": None, 
        "target": None, 
        "repository": github_metadata["repository"], 
        "commit_sha": github_metadata["commit_sha"], 
        "branch": github_metadata["branch"], 
        "github_run_id": github_metadata["github_run_id"], 
        "details": { 
            "commit": event.get("commit"), 
            "author": event.get("author"), 
            "email": event.get("email"), 
            "tags": event.get("tags") 
        }, 
        "source_type": "security_scan" } 


def normalize_dependency_check(event, github_metadata): 
    vulnerabilities = event.get("vulnerabilities", []) 
    normalized_events = [] 
	
    for vulnerability in vulnerabilities: 
        cvssv3 = vulnerability.get("cvssv3", {}) 
        normalized_events.append({ 
            "scanner": "dependency-check",
            "severity": vulnerability.get("severity"), 
            "rule_id": vulnerability.get("name"), 
            "message": vulnerability.get("description"), 
            "file": event.get("filePath"), 
            "line": None, 
            "package": event.get("packages", [{}])[0].get("id"), 
            "target": event.get("fileName"), 
            "repository": github_metadata["repository"], 
            "commit_sha": github_metadata["commit_sha"], 
            "branch": github_metadata["branch"], 
            "github_run_id": github_metadata["github_run_id"], 
            "details": { 
                "cvss_score": cvssv3.get("baseScore"), 
                "cvss_severity": cvssv3.get("baseSeverity"), 
                "cwes": vulnerability.get("cwes", []) 
            }, 
            "source_type": "security_scan" }) 
    return normalized_events 


def normalize_zap(alert, instance, github_metadata): 
    risk_mapping = { 
        "3": "HIGH", 
        "2": "MEDIUM", 
        "1": "LOW", 
        "0": "INFO" } 
    return { 
        "scanner": "zap", 
        "severity": risk_mapping.get(alert.get("riskcode")), 
        "rule_id": alert.get("pluginid"), 
        "message": alert.get("alert"), 
        "file": None, 
        "line": None, 
        "package": None, 
        "target": instance.get("uri"), 
        "repository": github_metadata["repository"], 
        "commit_sha": github_metadata["commit_sha"], 
        "branch": github_metadata["branch"], 
        "github_run_id": github_metadata["github_run_id"], 
        "details": { 
            "confidence": alert.get("confidence"), 
            "method": instance.get("method"), 
            "parameter": instance.get("param"), 
            "evidence": instance.get("evidence"), 
            "other_info": instance.get("otherinfo"), 
            "cwe_id": alert.get("cweid"), 
            "wasc_id": alert.get("wascid") 
        }, 
        "source_type": "security_scan" } 

def normalize_trivy(event, target, github_metadata): 
    cvss = event.get("CVSS", {}) 
    return { 
        "scanner": "trivy", 
        "severity": event.get("Severity"), 
        "rule_id": event.get("VulnerabilityID"), 
        "message": event.get("Title") or event.get("Description"), 
        "file": None, 
        "line": None, 
        "package": event.get("PkgName"), 
        "target": target, 
        "repository": github_metadata["repository"], 
        "commit_sha": github_metadata["commit_sha"], 
        "branch": github_metadata["branch"], 
        "github_run_id": github_metadata["github_run_id"], 
        "details": { 
            "installed_version": event.get("InstalledVersion"), 
            "fixed_version": event.get("FixedVersion"), 
            "status": event.get("Status"), 
            "cwes": event.get("CweIDs"), 
            "cvss": cvss 
        }, 
        "source_type": "security_scan" }



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

	if len(sys.argv) != 3: 
    	print("Usage: python3 collector.py <scanner> <report.json>") 
    	sys.exit(1)
	
	scanner = sys.argv[1] 
	filename = sys.argv[2] 

	with open(filename, "r" , encoding="utf-8") as file :
		data = json.load(file)

		
		if scanner == "bandit": 
			for event in data["results"]: 
				normalized_event = normalize_bandit(event,github_metadata) 
				send_event(normalized_event) 
				
		elif scanner == "semgrep": 
			for event in data["results"]: 
				normalized_event = normalize_semgrep(event,github_metadata) 
				send_event(normalized_event) 
				
		elif scanner == "gitleaks": 
    		for event in data: 
				normalized_event = normalize_gitleaks(event, github_metadata) 
				send_event(normalized_event) 		
				
		elif scanner == "dependency-check": 
			for dependency in data.get("dependencies", []): 
				normalized_events = normalize_dependency_check( dependency, github_metadata ) 
				for normalized_event in normalized_events: 
					send_event(normalized_event) 		

		elif scanner == "zap": 
		    for site in data.get("site", []): 
		    	for alert in site.get("alerts", []): 
		        	for instance in alert.get("instances", []): 
		                normalized_event = normalize_zap( alert, instance, github_metadata ) 
		                send_event(normalized_event) 
		elif scanner == "trivy": 
		    for result in data.get("Results", []): 
		        target = result.get("Target") 
		        for event in result.get("Vulnerabilities", []): 
		            normalized_event = normalize_trivy( event, target, github_metadata ) 
					send_event(normalized_event) 
		else: 
    		print(f"Unknown scanner: {scanner}") 
			sys.exit(1) 





	
		if isinstance(data, list) :
			for event in data :
				event["source_type"] = "security_scan"
				send_event(event)
		else :
			data["source_type"] = "security_scan"
			send_event(data)
if __name__ ==  "__main__" :
	main()
