# Background Agent Configuration Guide

## Overview

The Bug Hunting Framework includes a comprehensive background agent system designed to handle automated bug hunting tasks, stage execution, and workflow management.

## Quick Start

### 1. Initial Setup
```bash
./scripts/configure_agents.sh setup
./scripts/configure_agents.sh configure
```

### 2. Start Agents
```bash
./scripts/configure_agents.sh start
```

### 3. Check Status
```bash
./scripts/configure_agents.sh status
```

## Configuration

### Environment Variables

#### Agent Identity
- `AGENT_ID`: Unique agent identifier
- `AGENT_NAME`: Human-readable agent name
- `AGENT_VERSION`: Agent version
- `AGENT_ENVIRONMENT`: Environment (development/production)

#### Runtime Settings
- `AGENT_MAX_CONCURRENT_TASKS`: Maximum concurrent tasks
- `AGENT_TASK_TIMEOUT_SECONDS`: Task timeout
- `AGENT_HEARTBEAT_INTERVAL_SECONDS`: Health check interval
- `AGENT_RETRY_ATTEMPTS`: Retry attempts for failed tasks

#### Resource Limits
- `AGENT_MAX_MEMORY_MB`: Memory limit
- `AGENT_MAX_CPU_PERCENT`: CPU limit
- `AGENT_WORKER_REPLICAS`: Number of worker replicas

#### Security
- `AGENT_JWT_TOKEN_ROTATION_INTERVAL_HOURS`: Token rotation
- `AGENT_ENABLE_SSL_VERIFICATION`: SSL verification

## Management Commands

```bash
# Start agents
./scripts/configure_agents.sh start

# Stop agents
./scripts/configure_agents.sh stop

# Restart agents
./scripts/configure_agents.sh restart

# Check status
./scripts/configure_agents.sh status

# Scale workers
./scripts/configure_agents.sh scale

# View logs
./scripts/configure_agents.sh logs
```

## Docker Compose Services

### Agent Coordinator
- Central management service
- Task orchestration
- Health monitoring
- Metrics collection

### Agent Workers
- Scalable worker processes
- Task execution
- Resource management
- Auto-recovery

## Performance Optimization

### Resource Allocation
- Memory: 1-4GB per agent
- CPU: 20-80% depending on workload
- Storage: Shared volumes for outputs

### Scaling Strategies
- Horizontal: Add worker replicas
- Vertical: Increase resource limits
- Task distribution: Specialized workers

## Security Considerations

### Authentication
- JWT token management
- SSL verification
- Network isolation

### Access Control
- Docker socket access
- File system permissions
- Environment variables

## Monitoring

### Metrics
- Agent health status
- Task performance
- Resource usage
- Network activity

### Health Checks
- HTTP health endpoints
- Docker health checks
- Custom health scripts

## Troubleshooting

### Common Issues
1. Agent not starting
2. High resource usage
3. Network connectivity
4. Task failures

### Debug Mode
```bash
AGENT_DEBUG_MODE=true
AGENT_LOG_LEVEL=DEBUG
```

## Production Deployment

### Environment Setup
- Strong secrets
- SSL certificates
- Comprehensive monitoring
- Automated backups

### High Availability
- Load balancing
- Failover mechanisms
- Data persistence
- Health monitoring

## Best Practices

### Configuration
- Environment separation
- Secret management
- Version control
- Documentation

### Operations
- Automated testing
- Rollback procedures
- Change management
- Incident response

### Security
- Least privilege
- Regular updates
- Vulnerability scanning
- Access control

## Architecture

### Agent Types

1. **Agent Coordinator**: Central management service that orchestrates tasks and manages worker agents
2. **Agent Workers**: Scalable worker processes that execute individual bug hunting tasks
3. **Stage Containers**: Specialized containers for each bug hunting stage (passive recon, active recon, etc.)

### Agent Communication

- **REST API**: Communication with backend services
- **WebSocket**: Real-time status updates and task coordination
- **Docker Socket**: Direct container management for stage execution
- **Shared Volumes**: Output and cache sharing between agents

## Docker Compose Configuration

### Agent Coordinator Service

```yaml
agent_coordinator:
  build:
    context: .
    dockerfile: .cursor/Dockerfile
  container_name: bug-hunting-agent-coordinator
  restart: unless-stopped
  depends_on:
    backend:
      condition: service_healthy
  environment:
    - AGENT_ID=${AGENT_ID:-bug-hunting-agent-001}
    - AGENT_NAME=${AGENT_NAME:-Bug Hunting Framework Agent}
    - AGENT_MAX_CONCURRENT_TASKS=${AGENT_MAX_CONCURRENT_TASKS:-5}
    # ... other environment variables
  ports:
    - "9091:9091"  # Agent metrics
    - "6060:6060"  # Profiling (if enabled)
    - "5678:5678"  # Remote debug (if enabled)
  volumes:
    - ./:/home/ubuntu/projects/bug-hunting-framework
    - ./outputs:/home/ubuntu/projects/bug-hunting-framework/outputs
    - /var/run/docker.sock:/var/run/docker.sock
    - agent_logs:/var/log
    - agent_cache:/var/cache/agent
  networks:
    - bug-hunting-network
  deploy:
    resources:
      limits:
        memory: ${AGENT_MAX_MEMORY_MB:-2048}M
        cpus: '${AGENT_MAX_CPU_PERCENT:-80}%'
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:9091/health"]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 60s
```

### Agent Worker Service

```yaml
agent_worker:
  build:
    context: .
    dockerfile: .cursor/Dockerfile
  container_name: bug-hunting-agent-worker-${AGENT_WORKER_ID:-1}
  restart: unless-stopped
  depends_on:
    - agent_coordinator
    - backend
  environment:
    - AGENT_ID=bug-hunting-worker-${AGENT_WORKER_ID:-1}
    - AGENT_ROLE=worker
    - AGENT_COORDINATOR_URL=http://agent_coordinator:9091
    # ... other environment variables
  volumes:
    - ./:/home/ubuntu/projects/bug-hunting-framework
    - ./outputs:/home/ubuntu/projects/bug-hunting-framework/outputs
    - /var/run/docker.sock:/var/run/docker.sock
    - agent_logs:/var/log
    - agent_cache:/var/cache/agent
  networks:
    - bug-hunting-network
  deploy:
    replicas: ${AGENT_WORKER_REPLICAS:-2}
    resources:
      limits:
        memory: ${AGENT_WORKER_MEMORY_MB:-1024}M
        cpus: '${AGENT_WORKER_CPU_PERCENT:-50}%'
  healthcheck:
    test: ["CMD", "curl", "-f", "http://agent_coordinator:9091/worker/health"]
    interval: 30s
    timeout: 10s
    retries: 3
    start_period: 30s
```

## Monitoring and Metrics

### Available Metrics

1. **Agent Health**: Status, uptime, and responsiveness
2. **Task Performance**: Execution time, success rates, and errors
3. **Resource Usage**: CPU, memory, and disk utilization
4. **Network Activity**: API calls, WebSocket connections, and data transfer

### Monitoring Tools

1. **Prometheus**: Metrics collection and storage
2. **Grafana**: Visualization and alerting
3. **ELK Stack**: Log aggregation and analysis
4. **Custom Dashboards**: Framework-specific monitoring

### Alerting

Configure alerts for:
- Agent failures or restarts
- High resource usage
- Task execution failures
- Security events
- Performance degradation

## Support and Maintenance

### Regular Maintenance

1. **Log Rotation**: Configure automatic log rotation
2. **Cache Cleanup**: Regular cleanup of temporary data
3. **Health Checks**: Regular health check validation
4. **Performance Reviews**: Regular performance analysis

### Updates and Upgrades

1. **Version Management**: Track agent versions
2. **Rollback Strategy**: Plan for failed updates
3. **Testing**: Test updates in staging environment
4. **Documentation**: Update documentation with changes

### Support Resources

1. **Logs**: Primary source for troubleshooting
2. **Metrics**: Performance and health indicators
3. **Documentation**: Configuration and operation guides
4. **Community**: Framework community support 