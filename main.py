from scanner import GitlabScanner
import os

# Common settings
# URL and user token
gitlab_private_token = os.environ.get('gitlab_private_token')
gitlab_hostname = os.environ.get('gitlab_hostname', 'https://gitlab.com/')

if not gitlab_private_token:
    print('You must set gitlab_private_token and gitlab_hostname as environment variables')
    exit(1)

# How many pipelines should be checked per repository
# Set 0 for unlimited count
pipeline_count_to_check = int(os.environ.get('pipeline_count_to_check', 1))
check_for_false_positives = bool(os.environ.get('check_for_false_positives', True))

gitlab_scanner = GitlabScanner(
    gitlab_hostname=gitlab_hostname,
    gitlab_private_token=gitlab_private_token,
    check_for_false_positives=check_for_false_positives
)


def scan_logic():
    findings = list()
    group_ids = gitlab_scanner.get_all_groups()
    project_list = gitlab_scanner.get_all_projects(group_ids)
    for project in project_list:
        project_id = project.get('id')
        project_path_with_namespace = project.get('path_with_namespace')
        print(f'[{project_list.index(project)}/{len(project_list)}] Checking {project_path_with_namespace} | project id {project_id}')
        pipeline_list = gitlab_scanner.get_all_pipelines(project_id)

        pipeline_counter = 0
        for pipeline_id in pipeline_list:

            if pipeline_count_to_check > 0:
                if pipeline_counter >= pipeline_count_to_check:
                    break
            pipeline_counter += 1
            print(f'Checking pipeline {pipeline_id} | project id {project_id}')
            jobs = gitlab_scanner.get_all_pipeline_jobs(project_id, pipeline_id)
            traces = gitlab_scanner.get_all_job_traces(project_id, jobs)
            for trace in traces:
                result = gitlab_scanner.find_sensitive_data(trace.get('trace'))
                job_id = trace.get('job_id')
                if result is not None and not gitlab_scanner.detect_secret_false_positive(result):
                    finding = {
                        'project_id': project_id,
                        'project_path_with_namespace': project_path_with_namespace,
                        'pipeline_id': pipeline_id,
                        'link': f'{gitlab_hostname}/{project_path_with_namespace}/-/jobs/{job_id}',
                        'issue': f'Unmasked secret value: {result}'
                    }
                    print(finding)
                    findings.append(finding)
    return findings


print(f'First request to {gitlab_hostname}')
print(scan_logic())
