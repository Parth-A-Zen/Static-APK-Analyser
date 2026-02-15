FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for androguard
RUN apt-get update && apt-get install -y \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables to reduce logging
ENV PYTHONWARNINGS=ignore
ENV UVICORN_LOG_LEVEL=warning
ENV UVICORN_ACCESS_LOG=0

# Copy requirements first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create a non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Run the application
CMD uvicorn api.index:app --host 0.0.0.0 --port 8000 --log-level warning --access-log