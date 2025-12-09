# Use AWS's official pre-built kmstool container as base
# This container already has kmstool_enclave_cli and all dependencies
FROM public.ecr.aws/aws-nitro-enclaves/aws-nitro-enclaves-sdk-c:latest

# Install Python 3.11 and dependencies
RUN yum install -y python3.11 python3.11-pip && yum clean all

# Install Python dependencies
RUN pip3.11 install --no-cache-dir cryptography boto3

# Copy our application
WORKDIR /app
COPY app.py .
COPY run.sh .
RUN chmod +x run.sh

# kmstool_enclave_cli is already available at /usr/bin/kmstool_enclave from base image

CMD ["/app/run.sh"]
