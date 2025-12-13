# Rule Set Hot Reloading

This module provides hot reloading capabilities for router rule sets, allowing dynamic updates without service interruption.

## Features

- **File System Monitoring**: Automatic detection of rule set file changes using native file system events (when available) or polling fallback
- **Validation Before Apply**: New rule sets are validated before being applied to prevent service disruption
- **Rollback Mechanism**: Automatic rollback on validation failures or application errors
- **Service Continuity**: Hot reloads happen atomically without interrupting ongoing connections
- **Event Monitoring**: Real-time events for monitoring hot reload operations
- **CLI Tools**: Command-line utilities for managing and monitoring hot reloads

## Usage

### Basic Hot Reload Setup

```rust
use sb_core::router::{HotReloadConfig, HotReloadManager, RouterHandle};
use std::sync::Arc;
use std::time::Duration;

// Create configuration
let config = HotReloadConfig {
    enabled: true,
    check_interval: Duration::from_secs(5),
    rule_set_paths: vec![
        "/path/to/rules1.txt".into(),
        "/path/to/rules2.txt".into(),
    ],
    max_rules: 10000,
    ..Default::default()
};

// Create router handle
let router_handle = Arc::new(RouterHandle::from_env());

// Create and start hot reload manager
let mut manager = HotReloadManager::new(config, router_handle);
manager.start().await?;

// Hot reload is now active...

// Stop when done
manager.stop().await;
```

### Event Monitoring

```rust
// Get event receiver for monitoring
let mut event_rx = manager.event_receiver();

tokio::spawn(async move {
    loop {
        let event = match event_rx.recv().await {
            Ok(event) => event,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
        };
        match event {
            HotReloadEvent::FileChanged { path } => {
                println!("File changed: {}", path.display());
            }
            HotReloadEvent::Applied { path, generation } => {
                println!("Rules applied: {} (gen: {})", path.display(), generation);
            }
            HotReloadEvent::ValidationFailed { path, error } => {
                eprintln!("Validation failed for {}: {}", path.display(), error);
            }
            // ... handle other events
        }
    }
});
```

### CLI Usage

The hot reload functionality includes CLI tools for management:

```bash
# Start hot reload monitoring
rule-hot-reload start -f /path/to/rules.txt -i 5 --verbose

# Validate rule files
rule-hot-reload validate -f /path/to/rules1.txt -f /path/to/rules2.txt

# Show rule statistics
rule-hot-reload stats -f /path/to/rules.txt
```

## Configuration

### HotReloadConfig

- `enabled`: Enable/disable hot reloading
- `check_interval`: Polling interval when file system events are not available
- `validation_timeout`: Timeout for rule set validation
- `max_rollback_attempts`: Maximum number of rollback attempts
- `rule_set_paths`: List of rule set files to monitor
- `max_rules`: Maximum number of rules per rule set

### Environment Variables

- `SB_ROUTER_RULES_BASEDIR`: Base directory for relative rule file paths
- `SB_ROUTER_RULES_MAX_DEPTH`: Maximum include depth for rule files

## Rule Set Format

Rule sets use a simple text format:

```
# Comments start with #
exact:example.com=direct
suffix:google.com=proxy
cidr4:192.168.1.0/24=direct
cidr6:2001:db8::/32=proxy
port:443=proxy
portrange:8000-9000=direct
geoip:CN=direct
geosite:ads=reject
default=proxy
```

### Rule Types

- `exact:domain=decision`: Exact domain match
- `suffix:domain=decision`: Domain suffix match
- `cidr4:network/mask=decision`: IPv4 CIDR match
- `cidr6:network/mask=decision`: IPv6 CIDR match
- `port:port=decision`: Port match
- `portrange:start-end=decision`: Port range match
- `geoip:country=decision`: GeoIP country match
- `geosite:category=decision`: GeoSite category match
- `default=decision`: Default decision

### Decisions

Common decision values:
- `direct`: Direct connection
- `proxy`: Use proxy
- `reject`: Reject connection
- `block`: Block connection
- Custom outbound names

## Validation

Rule sets are validated before application:

1. **Syntax Validation**: Check rule syntax and format
2. **Limit Validation**: Ensure rule count doesn't exceed limits
3. **Semantic Validation**: Check for logical consistency
4. **Dependency Validation**: Verify required resources (GeoIP/GeoSite databases)

## Error Handling

### Validation Errors

- Invalid syntax in rule definitions
- Exceeding maximum rule limits
- Missing required resources
- Circular dependencies

### Application Errors

- Failed to acquire router lock
- Generation verification failure
- Resource allocation errors

### Rollback Scenarios

- Validation failures
- Application errors
- Service health check failures
- Manual rollback triggers

## Performance Considerations

### File System Monitoring

- Uses native file system events when available (inotify on Linux, FSEvents on macOS)
- Falls back to polling when native events are not available
- Configurable polling interval to balance responsiveness and resource usage

### Memory Usage

- Rule sets are validated in memory before application
- Old rule sets are garbage collected after successful application
- Memory usage scales with rule set size and number of monitored files

### CPU Impact

- Validation is CPU-intensive for large rule sets
- Hot reloads are performed asynchronously to avoid blocking routing decisions
- Configurable validation timeout to prevent excessive CPU usage

## Best Practices

### Rule Set Organization

1. **Modular Files**: Split rules into logical files (e.g., by category or source)
2. **Consistent Naming**: Use consistent file naming conventions
3. **Documentation**: Include comments explaining rule purposes
4. **Version Control**: Track rule set changes in version control

### Monitoring

1. **Event Logging**: Monitor hot reload events for operational visibility
2. **Metrics Collection**: Track reload frequency, validation failures, and performance
3. **Alerting**: Set up alerts for validation failures and rollbacks
4. **Health Checks**: Implement service health checks after rule updates

### Testing

1. **Validation Testing**: Test rule sets in staging before production
2. **Load Testing**: Verify performance impact of rule set changes
3. **Rollback Testing**: Test rollback scenarios and recovery procedures
4. **Integration Testing**: Test with actual traffic patterns

## Troubleshooting

### Common Issues

1. **File Permission Errors**: Ensure read access to rule set files and directories
2. **Validation Failures**: Check rule syntax and format
3. **Resource Limits**: Verify rule count doesn't exceed configured limits
4. **File System Events**: Check if file system supports native event monitoring

### Debugging

1. **Enable Verbose Logging**: Use verbose mode for detailed operation logs
2. **Check File Permissions**: Verify file and directory permissions
3. **Validate Manually**: Use CLI validation tools to check rule sets
4. **Monitor Events**: Watch hot reload events for error details

### Recovery

1. **Automatic Rollback**: System automatically rolls back on failures
2. **Manual Recovery**: Restore known-good rule sets manually
3. **Service Restart**: Restart service if hot reload system becomes unresponsive
4. **Configuration Reset**: Reset to default configuration if needed

## Security Considerations

### File Access

- Rule set files should have appropriate read permissions
- Prevent unauthorized modification of rule set files
- Monitor file system access for security events

### Validation Security

- Validate rule sets from trusted sources only
- Implement resource limits to prevent DoS attacks
- Sanitize rule content to prevent injection attacks

### Network Security

- Hot reload operations should not expose internal network topology
- Log security-relevant rule changes for audit trails
- Implement access controls for hot reload management interfaces
