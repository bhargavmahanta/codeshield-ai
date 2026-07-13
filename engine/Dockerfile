FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY codeshield ./codeshield
COPY tests ./tests

RUN pip install --no-cache-dir -e ".[dev]"

EXPOSE 8765

CMD ["codeshield", "server", "--host", "0.0.0.0", "--port", "8765"]
