FROM amazonlinux:2023

WORKDIR /app

# Install Python 3.11
RUN dnf install -y python3.11 python3.11-pip openssl openssl-devel gcc libffi-devel && dnf clean all

# Install dependencies
RUN pip3.11 install cryptography boto3 aws-nsm-interface

# Copy application
COPY app.py .
COPY run.sh .
RUN chmod +x run.sh

# Entrypoint
CMD ["/app/run.sh"]
