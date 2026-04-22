FROM python:3.11-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY dashboard/ ./dashboard/

RUN mkdir -p /data
ENV DB_PATH=/data/timetrack.db
ENV ADMIN_PASSWORD=changeme123

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
