FROM ubuntu:22.04

# Set non-interactive frontend for apt
ENV DEBIAN_FRONTEND=noninteractive

# Install required packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    sudo \
    nginx \
    curl \
    wget \
    git \
    vim \
    htop \
    net-tools \
    systemctl \
    && rm -rf /var/lib/apt/lists/*

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    sed -i 's/#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && \
    sed -i 's/#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#*UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

# Create user and set password
RUN useradd -m -s /bin/bash devuser && \
    echo 'devuser:ubuntupass' | chpasswd && \
    usermod -aG sudo devuser && \
    echo 'devuser ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/devuser && \
    chmod 0440 /etc/sudoers.d/devuser

# Setup welcome page
RUN echo '<h1>Welcome to your VM!</h1><p>SSH and Nginx are running.</p>' > /var/www/html/index.html

# Expose SSH and HTTP ports
EXPOSE 22 80

# Run SSH and Nginx in foreground
CMD ["/bin/bash", "-c", "service ssh start && service nginx start && tail -f /dev/null"]
