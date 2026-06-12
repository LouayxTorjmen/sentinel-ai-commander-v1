FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

# System packages:
#  - curl: healthcheck
#  - gcc + libffi-dev + libssl-dev: build deps for pywinrm/cryptography wheels
#  - openssh-client + sshpass: existing SSH transport support
#  - krb5-user libkrb5-dev: optional Kerberos for future AD attacks
RUN apt-get update && apt-get install -y \
        curl \
        gcc \
        libffi-dev \
        libssl-dev \
        openssh-client \
        sshpass \
        krb5-user \
        libkrb5-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /tmp/evidence

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Ansible Galaxy collections (community.mysql, ansible.windows, etc.)
# Installed to /root/.ansible/collections/ which is on default search path
COPY ansible-requirements.yml .
RUN ansible-galaxy collection install -r ansible-requirements.yml

# API server
COPY runner_api.py .
EXPOSE 5001
HEALTHCHECK --interval=30s --timeout=10s --retries=5 \
    CMD curl -f http://localhost:5001/health || exit 1
CMD ["python", "runner_api.py"]
