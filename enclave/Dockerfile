# Enclave Application

FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir --upgrade pip
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt --target /app/deps

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Copy dependencies and application
COPY --from=builder /app/deps /app/deps
COPY . .

ENV PYTHONPATH=/app/deps

# Enclave entry point
# Enclave entry point
COPY run.sh .
RUN chmod +x run.sh
CMD ["/app/run.sh"]
