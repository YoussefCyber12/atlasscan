# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY atlasscan ./atlasscan
RUN pip install . \
    && useradd --create-home --uid 10001 atlasscan

USER atlasscan
WORKDIR /home/atlasscan

# Results are written to /home/atlasscan/.atlasscan; mount a volume to keep them.
VOLUME ["/home/atlasscan/.atlasscan"]

ENTRYPOINT ["atlasscan"]
CMD ["--help"]
