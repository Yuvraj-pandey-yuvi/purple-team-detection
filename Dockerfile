FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for auditd access
RUN apt-get update && apt-get install -y \
    auditd \
    awscli \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Expose API port
EXPOSE 8000

# Run the API
CMD ["python3", "-m", "uvicorn", "dashboard.api:app", \
     "--host", "0.0.0.0", "--port", "8000"]