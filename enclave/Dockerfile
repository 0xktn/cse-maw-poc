# Temporary: Build from source until GHCR image is updated with fix
# TODO: Rebuild and push to GHCR, then switch back to pre-built image

FROM public.ecr.aws/amazonlinux/amazonlinux:2

# Install runtime dependencies
RUN yum install -y python3 python3-pip findutils && yum clean all

# For now, just copy a placeholder for kmstool_enclave_cli
# The actual binary will come from the GHCR image once it's updated
RUN echo "#!/bin/sh" > /usr/bin/kmstool_enclave_cli && \
    echo "echo 'Placeholder kmstool'" >> /usr/bin/kmstool_enclave_cli && \
    chmod +x /usr/bin/kmstool_enclave_cli

# Copy application
WORKDIR /app
COPY app.py requirements.txt run.sh ./

# Setup Python environment
RUN python3 -m venv venv && \
    ./venv/bin/pip install --no-cache-dir -r requirements.txt

CMD ["./run.sh"]
