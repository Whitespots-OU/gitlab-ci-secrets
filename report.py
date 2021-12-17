import json


def make_dojo_report(findings):
	report = {
		"findings": []
	}
	for finding in findings:
		report['findings'].append(
			{
				"unique_id_from_tool": str(findings.index(finding)),
				"title": "Unmasked Gitlab CI secret",
				"description": finding.get('issue', ''),
				"severity": "Medium",
				"url": finding.get('link', ''),
				"static_finding": False,
				"dynamic_finding": True
			}
		)
	return json.dumps(report) 
