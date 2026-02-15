FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for androguard
RUN apt-get update && apt-get install -y \
    default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create a non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Force shell expansion with sh -c
CMD sh -c "uvicorn api.index:app --host 0.0.0.0 --port $PORT"