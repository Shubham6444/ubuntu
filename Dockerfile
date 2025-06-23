FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install system packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    nginx \
    nodejs \
    npm \
    curl \
    wget \
    git \
    vim \
    htop \
    net-tools \
    snapd \
    && rm -rf /var/lib/apt/lists/*

# Install Certbot via Snap (recommended by Let's Encrypt)
apt-get update && apt-get install -y \
    software-properties-common && \
    add-apt-repository ppa:certbot/certbot -y && \
    apt-get update && apt-get install -y \
    certbot python3-certbot-nginx
# Configure SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

# Create devuser and give sudo access
RUN useradd -m -s /bin/bash devuser && \
    echo 'devuser:ubuntupass' | chpasswd && \
    usermod -aG sudo devuser && \
    echo 'devuser ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/devuser && \
    chmod 0440 /etc/sudoers.d/devuser && \
    adduser devuser ssl-cert


# Setup default Nginx page and ACME challenge directory
RUN mkdir -p /var/www/html/.well-known/acme-challenge && \
    echo '<h1>Welcome to your VM!</h1><p>Container is running!</p>' > /var/www/html/index.html

# Expose required ports
EXPOSE 22 80 443 3389

# Start services and keep the container running
CMD service ssh start && \
    service nginx start && \  
    tail -f /dev/null
