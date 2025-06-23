FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install all necessary packages
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
    certbot \
    python3-certbot-nginx \
    && rm -rf /var/lib/apt/lists/*

    RUN groupadd ssl-cert && \
    useradd -m -s /bin/bash devuser && \
    echo 'devuser:ubuntupass' | chpasswd && \
    usermod -aG sudo,ssl-cert devuser && \
    echo 'devuser ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/devuser && \
    chmod 0440 /etc/sudoers.d/devuser

# Configure SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config

# Create devuser and give sudo access
 RUN groupadd ssl-cert && \
    useradd -m -s /bin/bash devuser && \
    echo 'devuser:ubuntupass' | chpasswd && \
    usermod -aG sudo,ssl-cert devuser && \
    echo 'devuser ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/devuser && \
    chmod 0440 /etc/sudoers.d/devuser


# Setup default Nginx web page and ACME challenge folder
RUN mkdir -p /var/www/html/.well-known/acme-challenge && \
    echo '<h1>Welcome to your VM!</h1><p>Nginx and SSH running!</p>' > /var/www/html/index.html

# Expose required ports
EXPOSE 22 80 443

# Start SSH and Nginx services
CMD service ssh start && \
    service nginx start && \
    tail -f /dev/null
