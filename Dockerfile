FROM python:3-alpine3.12
LABEL maintainer="whitespots.io"

RUN adduser -D -u 1001 whitespots whitespots

COPY requirements.txt /app/

WORKDIR /app

RUN set -xe \
    && apk add --no-cache git jq curl \
    && pip install -r requirements.txt \
    && rm -rf /var/cache/apk/*

COPY . /app

USER whitespots
CMD ["python", "main.py"]
