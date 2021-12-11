from scanner import GitlabScanner
import os

# Common settings
# URL and user token
gitlab_private_token = ''
gitlab_hostname = os.environ.get('gitlab_hostname', '')

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

print(f'First request to {gitlab_hostname}')

trace = gitlab_scanner.get_all_job_traces(111, [1111111])
result = gitlab_scanner.find_sensitive_data(str(trace[0]))
print(result)