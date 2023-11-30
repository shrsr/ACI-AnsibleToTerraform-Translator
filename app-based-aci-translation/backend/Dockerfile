# Use an official Python runtime as a parent image
FROM python:3.9-slim-buster

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip

# Install any needed packages specified in requirements.txt
RUN pip install --upgrade pip && \
    pip install ansible flask flask_cors requests

# Install Golang
RUN wget https://golang.org/dl/go1.21.4.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.21.4.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin

# Install Terraform
RUN wget https://releases.hashicorp.com/terraform/1.6.3/terraform_1.6.3_linux_amd64.zip
RUN unzip terraform_1.6.3_linux_amd64.zip
RUN mv terraform /usr/local/bin/

# Install Cisco ACI Ansible Collection and Ansible Netcommon
RUN ansible-galaxy collection install cisco.aci:==2.8.0
RUN ansible-galaxy collection install ansible.netcommon:==5.3.0

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV FLASK_APP=server.py

# Set working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Download Go modules
RUN go mod download

# Make port 5000 available to the world outside this container
EXPOSE 5000

# Run server.py when the container launches
CMD ["flask", "run", "--host=0.0.0.0"]