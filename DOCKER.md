# QSSH Docker Guide

This guide covers running QSSH (Quantum Secure Shell) in Docker containers for easy deployment and testing.

## Quick Start

```bash
# Build the Docker image
./docker-build.sh

# Run QSSH server
./docker-run.sh

# Or use docker-compose
docker-compose up qsshd
```

## Docker Images

### Main Image: `qssh:latest`
- **Base**: Debian Bullseye Slim
- **Binaries**: qssh, qsshd, qscp
- **User**: Non-root `qssh` user
- **Port**: 22222
- **Size**: ~200MB (optimized multi-stage build)

## Build Options

```bash
# Standard build
./docker-build.sh

# No cache (clean build)
./docker-build.sh --no-cache

# Multi-platform build
./docker-build.sh --platform linux/amd64,linux/arm64

# Custom tag
./docker-build.sh --tag myregistry/qssh:v1.0
```

## Running Containers

### Server Mode
```bash
# Simple server
docker run -p 22222:22222 qssh:latest

# With persistent storage
docker run -p 22222:22222 \
  -v qssh_keys:/home/qssh/.qssh \
  -v qssh_logs:/var/log/qssh \
  qssh:latest

# Custom configuration
docker run -p 22222:22222 \
  -v ./my-qsshd.conf:/etc/qssh/qsshd.conf:ro \
  qssh:latest
```

### Client Mode
```bash
# Interactive client
docker run -it --rm qssh:latest qssh user@host

# File transfer
docker run -it --rm \
  -v $(pwd):/data \
  qssh:latest qscp /data/file.txt user@host:/remote/path
```

## Docker Compose

### Basic Setup
```bash
# Start server only
docker-compose up qsshd

# Start with client container for testing
docker-compose --profile client up

# Start with QKD simulator
docker-compose --profile qkd up
```

### Service Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   qssh-client   │◄──►│    qsshd        │◄──►│  qkd-simulator  │
│   (testing)     │    │   (server)      │    │   (optional)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
      Profile:              Default              Profile: qkd
      client
```

### Environment Variables
```yaml
environment:
  - QSSH_LOG_LEVEL=info          # debug, info, warn, error
  - QSSH_MAX_CONNECTIONS=100     # Maximum concurrent connections
  - QSSH_QRNG_ENDPOINT=          # Optional quantum RNG endpoint
  - QSSH_PQ_ALGORITHM=sphincs    # Post-quantum algorithm
```

## Volume Management

### Persistent Volumes
- **qssh_keys**: SSH keys and host keys
- **qssh_logs**: Server logs and audit trails
- **qssh_client_keys**: Client-side keys

```bash
# Backup volumes
docker run --rm -v qssh_keys:/data -v $(pwd):/backup alpine \
  tar czf /backup/qssh-keys-backup.tar.gz /data

# Restore volumes
docker run --rm -v qssh_keys:/data -v $(pwd):/backup alpine \
  tar xzf /backup/qssh-keys-backup.tar.gz -C /
```

## Security Configuration

### Production Hardening
```dockerfile
# Security-focused build
FROM qssh:latest

# Add security scanning
RUN apt-get update && apt-get install -y \
    rkhunter chkrootkit lynis

# Harden configuration
COPY production-qsshd.conf /etc/qssh/qsshd.conf
```

### Network Security
```yaml
# Restricted network
networks:
  qssh_secure:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.100.0/24
    driver_opts:
      com.docker.network.bridge.enable_icc: "false"
```

## Monitoring and Logging

### Health Checks
```bash
# Check container health
docker inspect qsshd-server | jq '.[0].State.Health'

# Manual health check
docker exec qsshd-server qssh -c "echo 'health check'" localhost
```

### Log Management
```bash
# View logs
docker logs qsshd-server

# Follow logs
docker logs -f qsshd-server

# Export logs
docker logs qsshd-server > qssh-server.log
```

## Quantum Features in Docker

### QKD Integration
```bash
# Start with QKD simulator
docker-compose --profile qkd up

# Connect to QKD endpoint
docker run -p 22222:22222 \
  -e QSSH_QKD_ENDPOINT=https://qkd-simulator:8443 \
  qssh:latest
```

### Quantum RNG
```bash
# Enable quantum random number generation
docker run -p 22222:22222 \
  -e QSSH_QRNG_ENDPOINT=https://qrng.anu.edu.au/API/jsonI.php \
  qssh:latest
```

## Development and Testing

### Development Mode
```bash
# Mount source code for development
docker run -it --rm \
  -v $(pwd):/app \
  -w /app \
  rust:1.70 \
  bash

# Hot reload development
docker-compose -f docker-compose.dev.yml up
```

### Testing
```bash
# Run tests in container
docker run --rm qssh:latest cargo test

# Integration testing
docker-compose exec qsshd qssh localhost echo "test"
```

## Troubleshooting

### Common Issues

1. **Port already in use**
   ```bash
   # Check what's using port 22222
   lsof -i :22222

   # Use different port
   docker run -p 2222:22222 qssh:latest
   ```

2. **Permission denied**
   ```bash
   # Check container user
   docker exec qsshd-server whoami

   # Fix volume permissions
   docker exec qsshd-server chown -R qssh:qssh /home/qssh/.qssh
   ```

3. **Connection refused**
   ```bash
   # Check if server is running
   docker exec qsshd-server ps aux | grep qsshd

   # Check logs
   docker logs qsshd-server
   ```

### Debug Mode
```bash
# Start with debug logging
docker run -p 22222:22222 \
  -e QSSH_LOG_LEVEL=debug \
  qssh:latest

# Interactive debugging
docker run -it --rm --entrypoint /bin/bash qssh:latest
```

## Production Deployment

### Container Orchestration
```yaml
# Kubernetes deployment example
apiVersion: apps/v1
kind: Deployment
metadata:
  name: qsshd
spec:
  replicas: 3
  selector:
    matchLabels:
      app: qsshd
  template:
    metadata:
      labels:
        app: qsshd
    spec:
      containers:
      - name: qsshd
        image: qssh:latest
        ports:
        - containerPort: 22222
        env:
        - name: QSSH_LOG_LEVEL
          value: "info"
```

### Load Balancing
```bash
# HAProxy configuration for QSSH
# /etc/haproxy/haproxy.cfg
backend qssh_servers
    balance roundrobin
    server qssh1 qsshd-1:22222 check
    server qssh2 qsshd-2:22222 check
    server qssh3 qsshd-3:22222 check
```

## Performance Tuning

### Resource Limits
```yaml
services:
  qsshd:
    image: qssh:latest
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### Scaling
```bash
# Scale with docker-compose
docker-compose up --scale qsshd=3

# Auto-scaling based on CPU
docker run --cpus="1.5" --memory="512m" qssh:latest
```

---

## Next Steps

- Configure production security settings
- Set up monitoring and alerting
- Integrate with your CI/CD pipeline
- Deploy to your container orchestration platform

For more information, see the main [QSSH documentation](README.md).