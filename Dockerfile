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
    xrdp \
    xfce4 xfce4-goodies \
    dbus-x11 x11-xserver-utils \
    && rm -rf /var/lib/apt/lists/*

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

# Configure XRDP to use XFCE
RUN echo "startxfce4" > /home/devuser/.xsession && \
    chown devuser:devuser /home/devuser/.xsession && \
    chmod +x /home/devuser/.xsession

# Welcome HTML for Nginx
RUN echo '<h1>Welcome to your VM!</h1><p>Container is running!</p>' > /var/www/html/index.html

# Enable xrdp on port 3389
EXPOSE 22 80 3389

# Start all services
CMD service ssh start && \
    service nginx start && \
    service xrdp-sesman start && \
    service xrdp start && \
    tail -f /dev/null
