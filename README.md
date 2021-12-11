# Simple gitlab CI secrets scanner

## The problem it solves

Many teams use non-masked GITLAB CI variables and print sensitive data in CI stdout.
This scanner will help you indentify such repositories and hide sensitive data then.

## How to run

1. Generate your `read_api` token
![token-generation](/images/token-generation.jpeg?raw=true "generation")
2. Run the following 

```
docker build -t whitespots/gitlab-ci-secrets .
docker run -it \
    -e "gitlab_private_token=<user_token_read_api>" \
    -e "gitlab_hostname=https://gitlab.com/" \
    -e "pipeline_count_to_check=1" \
    -e "check_for_false_positives=True" \
    whitespots/gitlab-ci-secrets
```

This latest version has the following parameters:
- `gitlab_private_token` (visit /-/profile/personal_access_tokens to get yours. Should have `read_api` access)
- `gitlab_hostname` to set your corporate gitlab. By default - `https://gitlab.com/`
- `pipeline_count_to_check` defines how many pipelines per one project to scan. By default - `1`. Set `0` for unlimited
- `check_for_false_positives` is `True` by default. It checks for `${` constructions in findings to avoid FPs

You can add any custom pattern in `patterns.json` and mount it to your docker container like:
```
docker run -it \
    -e "gitlab_private_token=<user_token_read_api>" \
    -e "gitlab_hostname=https://gitlab.com/" \
    -e "pipeline_count_to_check=1" \
    -e "check_for_false_positives=True" \
    -v $(pwd):/app
    whitespots/gitlab-ci-secrets
```

## Next features
- Passing config path as an argument
- DefectDojo integration

