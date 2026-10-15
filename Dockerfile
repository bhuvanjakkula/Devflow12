FROM python:3.12-slim
WORKDIR /srv/app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements-production.lock ./
RUN pip install --no-cache-dir -r requirements-production.lock
COPY app ./app
COPY static ./static
COPY backup.py ops_cli.py ./
RUN groupadd --system devflow && useradd --system --gid devflow --home-dir /srv/app devflow && mkdir -p /srv/app/data && chown -R devflow:devflow /srv/app
USER devflow
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
