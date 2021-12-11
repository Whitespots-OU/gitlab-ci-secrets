import requests
import re
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
pipeline_count_to_check = 1
check_for_false_positives = True

group_list = list()
project_list = list()


def get_all_groups():
    """
    First important step - get all availiable groups
    :return:
    """
    print('Getting all groups')
    # Get pages count
    response = requests.get(
        url=f'{gitlab_hostname}/api/v4/groups?all_available=true&page=1&per_page=30',
        headers={
            'PRIVATE-TOKEN': gitlab_private_token
        }
    )
    total_pages = int(response.headers.get('x-total-pages'))
    distinct_id_list = list()
    # Getting data from all groups
    for page_index in range(1, total_pages+1):
        response = requests.get(
            url=f'{gitlab_hostname}/api/v4/groups?all_available=true&page={page_index}&per_page=30',
            headers={
                'PRIVATE-TOKEN': gitlab_private_token
            }
        )
        try:
            distinct_id_list.extend(list(set([group.get('id') for group in response.json()])))
        except:
            break
    return distinct_id_list


def get_all_projects(group_id_list):
    """
    This function gets all projects within all gitlab groups & subgroups. We don't care about them
    :param group_id_list:
    :return:
    """
    print('Getting all projects')
    distinct_id_list = list()

    for group_id in group_id_list:
        # Get pages count
        response = requests.get(
            url=f'{gitlab_hostname}/api/v4/groups/{group_id}/projects?include_subgroups=true&page=1&per_page=30',
            headers={
                'PRIVATE-TOKEN': gitlab_private_token
            }
        )
        total_pages = int(response.headers.get('x-total-pages'))

        # Getting data from all groups
        for page_index in range(1, total_pages + 1):
            response = requests.get(
                url=f'{gitlab_hostname}/api/v4/groups/{group_id}/projects?include_subgroups=true&page={page_index}&per_page=30',
                headers={
                    'PRIVATE-TOKEN': gitlab_private_token
                }
            )
        try:
            for item in response.json():
                if item.get('id') not in distinct_id_list:
                    distinct_id_list.append(item)
        except Exception as ex:
            print(f'get_all_projects failure: {ex}')
    return distinct_id_list


def get_all_pipelines(project_id):
    """
    Actually not all. Gitlab will return only 20 pipelines due to pagination.
    We don't need all of them. You may set the scan depth by setting pipeline_count_to_check to any proper value.
    :param project_id:
    :return:
    """
    print('Getting all pipelines')
    distinct_id_list = list()
    response = requests.get(
        url=f'{gitlab_hostname}/api/v4/projects/{project_id}/pipelines?scope=finished',
        headers={
            'PRIVATE-TOKEN': gitlab_private_token
        }
    ).json()
    try:
        for item in response:
            if item.get('id') not in distinct_id_list:
                distinct_id_list.append(item.get('id'))
    except Exception as ex:
        print(f'get_all_pipelines failure: {ex}')
    return distinct_id_list


def get_all_pipeline_jobs(project_id, pipeline_id):
    """
    Return jobs to parse their RAW output then
    :param project_id:
    :param pipeline_id:
    :return:
    """
    print('Getting all pipeline jobs')
    distinct_id_list = list()
    response = requests.get(
        url=f'{gitlab_hostname}/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs',
        headers={
            'PRIVATE-TOKEN': gitlab_private_token
        }
    ).json()
    try:
        for item in response:
            if item.get('id') not in distinct_id_list:
                distinct_id_list.append(item.get('id'))
    except Exception as ex:
        print(f'get_all_pipeline_jobs failure: {ex}')
    return distinct_id_list


def get_all_job_traces(project_id, job_id_list):
    """
    Get jobs RAW output to search for secrets
    :param project_id:
    :param job_id_list:
    :return:
    """
    traces = list()
    for job_id in job_id_list:
        response = requests.get(
            url=f'{gitlab_hostname}/api/v4/projects/{project_id}/jobs/{job_id}/trace',
            headers={
                'PRIVATE-TOKEN': gitlab_private_token
            }
        ).text
        traces.append(response)
    return traces


def find_sensitive_data(trace):
    result = re.findall(r'(?:token|secret|password|private)=(.*)', trace, re.IGNORECASE)
    # re.match(r'(?:token|secret|password|private)=(.*)', trace)
    if result is not None and len(result) > 0:
        if any([detect_secret_false_positive(match) for match in result]):
            return None
        return result
    return None


def detect_secret_false_positive(finding):
    if not check_for_false_positives:
        return False
    if '${' in finding:
        return True


def scan_logic():
    findings = list()
    group_ids = get_all_groups()
    project_list = get_all_projects(group_ids)
    for project in project_list:
        project_id = project.get('id')
        project_path_with_namespace = project.get('path_with_namespace')
        print(f'[{project_list.index(project)}/{len(project_list)}] Checking {project_path_with_namespace} | project id {project_id}')
        pipeline_list = get_all_pipelines(project_id)

        pipeline_counter = 0
        for pipeline_id in pipeline_list:

            if pipeline_count_to_check > 0:
                if pipeline_counter >= pipeline_count_to_check:
                    break
            pipeline_counter += 1
            print(f'Checking pipeline {pipeline_id} | project id {project_id}')
            jobs = get_all_pipeline_jobs(project_id, pipeline_id)
            traces = get_all_job_traces(project_id, jobs)
            for trace in traces:
                result = find_sensitive_data(trace)
                if result is not None and not detect_secret_false_positive(result):
                    finding = {
                        'project_id': project_id,
                        'project_path_with_namespace': project_path_with_namespace,
                        'pipeline_id': pipeline_id,
                        'issue': f'Unmasked secret value: {result}'
                    }
                    print(finding)
                    findings.append(finding)
    return findings


print(f'First request to {gitlab_hostname}')
print(scan_logic())
