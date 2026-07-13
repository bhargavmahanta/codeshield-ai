FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY codeshield ./codeshield
COPY tests ./tests

RUN pip install --no-cache-dir -e ".[dev]"

EXPOSE 8765

CMD ["codeshield", "server", "--host", "0.0.0.0", "--port", "8765"]

