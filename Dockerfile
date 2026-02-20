# Use slim Python image
FROM python:3.11-slim

# Install ping utility
RUN apt-get update && \
    apt-get install -y iputils-ping && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory inside container
WORKDIR /app

# Copy project files
COPY scanner.py .
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create output folder inside container
RUN mkdir -p /app/output

# Default command
ENTRYPOINT ["python", "scanner.py"]
CMD ["--help"]
