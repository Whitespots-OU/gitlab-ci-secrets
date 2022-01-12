import requests
import re
from config import load_config


class GitlabScanner:
    def __init__(self, gitlab_hostname, gitlab_private_token, check_for_false_positives):
        self.gitlab_hostname = gitlab_hostname
        self.gitlab_private_token = gitlab_private_token
        self.check_for_false_positives = check_for_false_positives

    def get_all_groups(self):
        """
        First important step - get all availiable groups
        :return:
        """
        print('Getting all groups')
        # Get pages count
        response = requests.get(
            url=f'{self.gitlab_hostname}/api/v4/groups?all_available=true&page=1&per_page=5',
            headers={
                'PRIVATE-TOKEN': self.gitlab_private_token
            }
        )
        total_pages = int(response.headers.get('x-total-pages'))
        distinct_id_list = list()
        # Getting data from all groups
        for page_index in range(1, total_pages + 1):
            response = requests.get(
                url=f'{self.gitlab_hostname}/api/v4/groups?all_available=true&page={page_index}&per_page=80',
                headers={
                    'PRIVATE-TOKEN': self.gitlab_private_token
                }
            )
            try:
                distinct_id_list.extend(list(set([group.get('id') for group in response.json()])))
            except:
                break
        return distinct_id_list

    def get_all_projects(self, group_id_list):
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
                url=f'{self.gitlab_hostname}/api/v4/groups/{group_id}/projects?include_subgroups=true&page=1&per_page=5',
                headers={
                    'PRIVATE-TOKEN': self.gitlab_private_token
                }
            )
            total_pages = int(response.headers.get('x-total-pages'))

            # Getting data from all groups
            for page_index in range(1, total_pages + 1):
                print(f'[{group_id_list.index(group_id)}/{len(group_id_list)}] '
                      f'Getting projects for group id {group_id}. Page {page_index}/{total_pages}...')
                response = requests.get(
                    url=f'{self.gitlab_hostname}/api/v4/groups/{group_id}/projects?include_subgroups=true&page={page_index}&per_page=80',
                    headers={
                        'PRIVATE-TOKEN': self.gitlab_private_token
                    }
                )
                try:
                    for item in response.json():
                        if item.get('id') not in distinct_id_list:
                            distinct_id_list.append(item)
                except Exception as ex:
                    print(f'get_all_projects failure: {ex}')
        return distinct_id_list

    def get_all_pipelines(self, project_id):
        """
        Actually not all. Gitlab will return only 20 pipelines due to pagination.
        We don't need all of them. This function will give you some, but then only one pipeline will be used.
        You may set the scan depth by setting pipeline_count_to_check to any proper value.
        :param project_id:
        :return:
        """
        print('Getting all pipelines')
        distinct_id_list = list()
        response = requests.get(
            url=f'{self.gitlab_hostname}/api/v4/projects/{project_id}/pipelines?scope=finished',
            headers={
                'PRIVATE-TOKEN': self.gitlab_private_token
            }
        ).json()
        try:
            for item in response:
                if item.get('id') not in distinct_id_list:
                    distinct_id_list.append(item.get('id'))
        except Exception as ex:
            print(f'get_all_pipelines failure: {ex}')
        return distinct_id_list

    def get_all_pipeline_jobs(self, project_id, pipeline_id):
        """
        Return jobs to parse their RAW output then
        :param project_id:
        :param pipeline_id:
        :return:
        """
        print('Getting all jobs')
        distinct_id_list = list()
        response = requests.get(
            url=f'{self.gitlab_hostname}/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs',
            headers={
                'PRIVATE-TOKEN': self.gitlab_private_token
            }
        ).json()
        try:
            for item in response:
                if item.get('id') not in distinct_id_list:
                    distinct_id_list.append(item.get('id'))
        except Exception as ex:
            print(f'get_all_pipeline_jobs failure: {ex}')
        return distinct_id_list

    def get_all_job_traces(self, project_id, job_id_list):
        """
        Get jobs RAW output to search for secrets
        :param project_id:
        :param job_id_list:
        :return:
        """
        traces = list()
        for job_id in job_id_list:
            response = requests.get(
                url=f'{self.gitlab_hostname}/api/v4/projects/{project_id}/jobs/{job_id}/trace',
                headers={
                    'PRIVATE-TOKEN': self.gitlab_private_token
                }
            ).text
            traces.append({
                'job_id': job_id,
                'trace': response
            })
        return traces

    def find_sensitive_data(self, trace):
        patterns = load_config()
        for rule in patterns.get('finding'):
            pattern = re.compile(
                patterns.get('finding').get(rule), re.IGNORECASE
            )
            result = pattern.findall(trace)
            if result is not None and len(result) > 0:
                if any([self.detect_secret_false_positive(match) for match in result]):
                    return None
                return result
        return None

    def detect_secret_false_positive(self, match):
        print(f'Checking {match} is false positive or not')
        if not self.check_for_false_positives:
            return False
        if len(match) == 0:
            return True

        patterns = load_config()
        for finding in match:
            if type(finding) is type(tuple()):
                for part in finding:
                    if part.startswith('$'):
                        return True
                    for rule in patterns.get('false_positive'):
                        pattern_list = patterns.get('false_positive').get(rule)
                        if type(pattern_list) is type(list()):
                            for pattern in pattern_list:
                                regexp = re.compile(pattern, re.IGNORECASE)
                                result = regexp.findall(str(part))
                                if result is not None and len(result) > 0:
                                    return True
            if type(finding) is type(str()):
                if finding.startswith('$'):
                    return True
                for rule in patterns.get('false_positive'):
                    pattern_list = patterns.get('false_positive').get(rule)
                    if type(pattern_list) is type(list()):
                        for pattern in pattern_list:
                            regexp = re.compile(pattern, re.IGNORECASE)
                            result = regexp.findall(str(finding))
                            if result is not None and len(result) > 0:
                                return True
        return False
