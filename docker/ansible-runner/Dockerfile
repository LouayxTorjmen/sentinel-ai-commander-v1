FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y curl gcc openssh-client sshpass && apt-get clean && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY runner_api.py .
EXPOSE 5001
HEALTHCHECK --interval=30s --timeout=10s --retries=5 CMD curl -f http://localhost:5001/health || exit 1
CMD ["python", "runner_api.py"]
