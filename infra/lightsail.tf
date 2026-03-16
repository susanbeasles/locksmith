# Lightsail instance — browser proxy with TLS interception
resource "aws_lightsail_instance" "locksmith" {
  name              = "locksmith-${var.environment}"
  availability_zone = var.lightsail_availability_zone
  blueprint_id      = "amazon_linux_2023"
  bundle_id         = var.lightsail_instance_size

  user_data = <<-USERDATA
    #!/bin/bash
    set -euo pipefail

    # Install Node.js 20
    curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
    yum install -y nodejs git

    # Create locksmith user
    useradd -m -s /bin/bash locksmith

    # Create app directory
    mkdir -p /opt/locksmith
    chown locksmith:locksmith /opt/locksmith

    # Create systemd service
    cat > /etc/systemd/system/locksmith.service << 'EOF'
    [Unit]
    Description=Locksmith Credential Proxy
    After=network.target

    [Service]
    Type=simple
    User=locksmith
    WorkingDirectory=/opt/locksmith
    ExecStart=/usr/bin/node src/index.js
    Restart=always
    RestartSec=5
    Environment=NODE_ENV=production
    EnvironmentFile=/opt/locksmith/.env

    # Security hardening
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    ReadWritePaths=/opt/locksmith /var/log/locksmith
    PrivateTmp=yes

    [Install]
    WantedBy=multi-user.target
    EOF

    # Create log directory
    mkdir -p /var/log/locksmith
    chown locksmith:locksmith /var/log/locksmith

    systemctl daemon-reload
    systemctl enable locksmith
  USERDATA

  tags = {
    Name = "locksmith-${var.environment}"
  }
}

# Static IP for the Lightsail instance
resource "aws_lightsail_static_ip" "locksmith" {
  name = "locksmith-ip-${var.environment}"
}

resource "aws_lightsail_static_ip_attachment" "locksmith" {
  static_ip_name = aws_lightsail_static_ip.locksmith.name
  instance_name  = aws_lightsail_instance.locksmith.name
}

# No public ports — all access via pre-provisioned tunnel (CF/VPN)
# Lightsail requires at least one port_info block, so we allow SSH
# from nowhere (the firewall on the box drops everything anyway)
resource "aws_lightsail_instance_public_ports" "locksmith" {
  instance_name = aws_lightsail_instance.locksmith.name

  # Lightsail API requires at least one port rule
  # The instance-level iptables DROP ALL makes this irrelevant
  port_info {
    protocol  = "tcp"
    from_port = 22
    to_port   = 22
    cidrs     = [] # no CIDRs = no access
  }
}
