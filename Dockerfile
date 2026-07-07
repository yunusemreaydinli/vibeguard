FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port for ADK web UI
EXPOSE 8000

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run with ADK web interface
CMD ["adk", "web", "vibeguard"]
