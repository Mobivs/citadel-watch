# Rate Limiting Behavior Documentation

## For Test Agents and API Clients

This document describes how rate limiting works in Citadel Archer and how test agents should respond to rate limit errors.

### Rate Limit Response

When you hit a rate limit, the API will return:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 60

{
  "error": "Rate limit exceeded",
  "message": "Too many requests from this agent",
  "retry_after": 60,
  "agent_id": "your-agent-id"
}
```

### How Test Agents Should Handle Rate Limits

#### 1. **Immediate Response**
When you receive a 429 status code:
- **STOP** making requests immediately
- **DO NOT** retry the same request in a loop
- **DO NOT** ignore the rate limit and continue

#### 2. **Exponential Backoff**
Implement exponential backoff with jitter:

```python
import time
import random

class TestAgent:
    def __init__(self):
        self.backoff_seconds = 1
        self.max_backoff = 300  # 5 minutes max
        
    def handle_rate_limit(self, retry_after=None):
        """Handle 429 rate limit response."""
        # Use server's Retry-After if provided
        if retry_after:
            wait_time = retry_after
        else:
            # Otherwise use exponential backoff
            wait_time = self.backoff_seconds
            
        # Add jitter to prevent thundering herd
        jitter = random.uniform(0, wait_time * 0.1)
        actual_wait = wait_time + jitter
        
        print(f"Rate limited. Waiting {actual_wait:.1f} seconds...")
        time.sleep(actual_wait)
        
        # Increase backoff for next time
        self.backoff_seconds = min(self.backoff_seconds * 2, self.max_backoff)
    
    def reset_backoff(self):
        """Reset backoff after successful request."""
        self.backoff_seconds = 1
    
    def make_request(self, url, data):
        """Make API request with rate limit handling."""
        response = requests.post(url, json=data)
        
        if response.status_code == 429:
            # Get Retry-After header if present
            retry_after = response.headers.get('Retry-After')
            if retry_after:
                retry_after = int(retry_after)
            
            self.handle_rate_limit(retry_after)
            return None  # Don't retry immediately
            
        elif response.status_code == 200:
            self.reset_backoff()  # Successful request, reset backoff
            return response.json()
        
        return None
```

#### 3. **Circuit Breaker Pattern**
For production agents, implement a circuit breaker:

```python
class CircuitBreaker:
    def __init__(self, failure_threshold=5, recovery_timeout=60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.last_failure_time = None
        self.state = "closed"  # closed, open, half-open
    
    def call(self, func, *args, **kwargs):
        if self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half-open"
            else:
                raise Exception("Circuit breaker is open")
        
        try:
            result = func(*args, **kwargs)
            if self.state == "half-open":
                self.state = "closed"
                self.failure_count = 0
            return result
        except RateLimitException:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                print(f"Circuit breaker opened after {self.failure_count} failures")
            raise
```

### Rate Limit Thresholds

Current default limits (subject to configuration):

| Endpoint Type | Requests | Time Window | Burst Allowed |
|--------------|----------|-------------|---------------|
| Read Operations | 100 | 1 minute | Yes (150) |
| Write Operations | 20 | 1 minute | No |
| WebSocket | 10 | 1 second | Yes (20) |
| Authentication | 5 | 5 minutes | No |

### Log Throttling

To prevent log spam from rate-limited agents:

1. **First occurrence**: Full error logged
2. **Subsequent occurrences**: Logged once per minute per agent
3. **Summary**: Every 5 minutes, a summary of suppressed messages is logged

Example log output:
```
[INFO] Rate limit hit by agent test-agent-1
[THROTTLE] Suppressed 47 similar messages from test-agent-1 in last minute
[SUMMARY] LOG THROTTLE: Suppressed 523 messages | Top sources: test-agent-1: 347, test-agent-2: 176
```

### Best Practices for Test Agents

1. **Batch Operations**: Combine multiple operations into single requests when possible
2. **Caching**: Cache read-only data to reduce API calls
3. **Webhooks**: Use webhooks/websockets for real-time updates instead of polling
4. **Rate Limit Headers**: Always check response headers for rate limit info:
   - `X-RateLimit-Limit`: Maximum requests allowed
   - `X-RateLimit-Remaining`: Requests remaining
   - `X-RateLimit-Reset`: Unix timestamp when limit resets
   - `Retry-After`: Seconds to wait before retrying

### Example: Well-Behaved Test Agent

```python
import time
import requests
from datetime import datetime

class WellBehavedTestAgent:
    def __init__(self, agent_id):
        self.agent_id = agent_id
        self.session = requests.Session()
        self.backoff = 1
        
    def run_test_cycle(self):
        """Run a test cycle with proper rate limit handling."""
        
        # Check rate limit status first
        if not self.check_rate_limit_status():
            print(f"[{self.agent_id}] Approaching rate limit, slowing down...")
            time.sleep(5)
        
        # Make requests with backoff
        for i in range(10):
            success = self.make_test_request()
            
            if not success:
                print(f"[{self.agent_id}] Backing off for {self.backoff}s")
                time.sleep(self.backoff)
                self.backoff = min(self.backoff * 2, 60)
            else:
                self.backoff = max(1, self.backoff * 0.9)  # Slowly reduce backoff
                time.sleep(0.5)  # Small delay between successful requests
    
    def check_rate_limit_status(self):
        """Check remaining rate limit."""
        response = self.session.head("http://api/status")
        remaining = int(response.headers.get("X-RateLimit-Remaining", 100))
        return remaining > 20  # Keep buffer of 20 requests
    
    def make_test_request(self):
        """Make a test request with proper error handling."""
        try:
            response = self.session.post(
                "http://api/test",
                json={"agent_id": self.agent_id, "timestamp": datetime.now().isoformat()}
            )
            
            if response.status_code == 429:
                return False
            elif response.status_code == 200:
                return True
            else:
                print(f"Unexpected status: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"Request failed: {e}")
            return False
```

### Monitoring Your Agent's Behavior

Check the audit log monitor status to see if your agent is causing issues:

```bash
cat /opt/citadel-archer-prod/audit_logs/monitor_status.json
```

If your agent appears in the "top offenders" list, it needs to implement better rate limiting.

## Summary

**DO:**
- ✅ Respect rate limits immediately
- ✅ Implement exponential backoff
- ✅ Use Retry-After headers
- ✅ Add jitter to prevent thundering herd
- ✅ Cache data when possible
- ✅ Monitor your agent's impact

**DON'T:**
- ❌ Ignore 429 responses
- ❌ Retry in tight loops
- ❌ Spawn multiple agents to bypass limits
- ❌ Log every rate limit hit (it makes the problem worse)
- ❌ Assume limits won't change

Remember: A well-behaved test agent is a **good citizen** of the system. Rate limits protect the service for everyone.