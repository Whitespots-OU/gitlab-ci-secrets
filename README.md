# Simple gitlab CI secrets scanner

## Problem

Many teams use non-masked GITLAB CI variables and print sensitive data in CI stdout.
This scanner will help you indentify such repositories and hide sensitive data then.

## How to run

```
docker build -t whitespots/gitlab-ci-secrets .
docker run -it -e "gitlab_private_token=<user_token_read_api>" -e "gitlab_hostname=https://gitlab.com/" whitespots/gitlab-ci-secrets
```
