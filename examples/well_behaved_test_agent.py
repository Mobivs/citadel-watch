#!/usr/bin/env python3
"""
Example of a well-behaved test agent that properly handles rate limits.

This demonstrates:
1. Exponential backoff when rate limited
2. Checking rate limit headers
3. Circuit breaker pattern
4. Proper logging without spam
"""

import time
import random
import requests
from datetime import datetime
from typing import Optional, Dict, Any


class RateLimitHandler:
    """Handle rate limiting with exponential backoff."""
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.backoff_seconds = 1.0
        self.max_backoff = 300.0  # 5 minutes max
        self.consecutive_failures = 0
        
    def handle_rate_limit(self, retry_after: Optional[int] = None) -> float:
        """Calculate and apply backoff for rate limiting."""
        self.consecutive_failures += 1
        
        # Use server's Retry-After if provided
        if retry_after:
            wait_time = float(retry_after)
        else:
            # Exponential backoff with jitter
            wait_time = min(
                self.backoff_seconds * (2 ** self.consecutive_failures),
                self.max_backoff
            )
        
        # Add jitter to prevent thundering herd
        jitter = random.uniform(0, wait_time * 0.1)
        actual_wait = wait_time + jitter
        
        print(f"[{self.agent_id}] Rate limited (attempt {self.consecutive_failures}). "
              f"Waiting {actual_wait:.1f} seconds...")
        
        return actual_wait
    
    def reset(self):
        """Reset backoff after successful request."""
        if self.consecutive_failures > 0:
            print(f"[{self.agent_id}] Rate limit cleared, resuming normal operation")
        self.consecutive_failures = 0
        self.backoff_seconds = 1.0


class CircuitBreaker:
    """Circuit breaker to prevent hammering a struggling service."""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.last_failure_time: Optional[float] = None
        self.state = "closed"  # closed, open, half-open
    
    def record_success(self):
        """Record a successful call."""
        if self.state == "half-open":
            print("Circuit breaker: Recovered, closing circuit")
            self.state = "closed"
            self.failure_count = 0
    
    def record_failure(self):
        """Record a failed call."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        
        if self.failure_count >= self.failure_threshold:
            if self.state != "open":
                print(f"Circuit breaker: Opening after {self.failure_count} failures")
            self.state = "open"
    
    def can_attempt(self) -> bool:
        """Check if we can attempt a call."""
        if self.state == "closed":
            return True
        
        if self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                print("Circuit breaker: Attempting recovery (half-open)")
                self.state = "half-open"
                return True
            return False
        
        # half-open
        return True


class WellBehavedTestAgent:
    """Example of a test agent that handles rate limits properly."""
    
    def __init__(self, agent_id: str, api_base: str = "http://localhost:8443"):
        self.agent_id = agent_id
        self.api_base = api_base
        self.session = requests.Session()
        self.rate_limit_handler = RateLimitHandler(agent_id)
        self.circuit_breaker = CircuitBreaker()
        
        # Track metrics
        self.requests_made = 0
        self.requests_rate_limited = 0
        self.total_wait_time = 0.0
        
    def make_request(self, endpoint: str, method: str = "GET", 
                    data: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Make an API request with proper error handling."""
        
        # Check circuit breaker
        if not self.circuit_breaker.can_attempt():
            print(f"[{self.agent_id}] Circuit breaker is open, skipping request")
            return None
        
        url = f"{self.api_base}/{endpoint}"
        self.requests_made += 1
        
        try:
            # Make the request
            if method == "GET":
                response = self.session.get(url)
            elif method == "POST":
                response = self.session.post(url, json=data or {})
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            # Check for rate limiting
            if response.status_code == 429:
                self.requests_rate_limited += 1
                self.circuit_breaker.record_failure()
                
                # Get Retry-After header
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    retry_after = int(retry_after)
                
                # Handle rate limit
                wait_time = self.rate_limit_handler.handle_rate_limit(retry_after)
                self.total_wait_time += wait_time
                time.sleep(wait_time)
                
                return None  # Don't retry immediately
            
            # Check for other errors
            if response.status_code >= 500:
                self.circuit_breaker.record_failure()
                print(f"[{self.agent_id}] Server error: {response.status_code}")
                return None
            
            # Success!
            self.rate_limit_handler.reset()
            self.circuit_breaker.record_success()
            
            # Check rate limit headers
            remaining = response.headers.get('X-RateLimit-Remaining')
            if remaining and int(remaining) < 10:
                print(f"[{self.agent_id}] Warning: Only {remaining} requests remaining")
                # Proactively slow down
                time.sleep(1.0)
            
            if response.status_code == 200:
                return response.json() if response.text else {}
            else:
                print(f"[{self.agent_id}] Unexpected status: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.circuit_breaker.record_failure()
            print(f"[{self.agent_id}] Request failed: {e}")
            return None
    
    def run_test_cycle(self, num_requests: int = 100, request_delay: float = 0.1):
        """Run a test cycle with proper rate limit handling."""
        print(f"\n{'='*60}")
        print(f"Starting test cycle for agent: {self.agent_id}")
        print(f"Requests to make: {num_requests}")
        print(f"Base delay between requests: {request_delay}s")
        print(f"{'='*60}\n")
        
        start_time = time.time()
        successful_requests = 0
        
        for i in range(num_requests):
            # Make a test request
            result = self.make_request(
                "test",
                "POST",
                {
                    "agent_id": self.agent_id,
                    "request_num": i + 1,
                    "timestamp": datetime.now().isoformat()
                }
            )
            
            if result:
                successful_requests += 1
                if (i + 1) % 10 == 0:
                    print(f"[{self.agent_id}] Progress: {i + 1}/{num_requests} requests")
            
            # Add base delay between requests
            time.sleep(request_delay)
            
            # Additional delay if we're seeing high failure rate
            if i > 10 and successful_requests / (i + 1) < 0.5:
                print(f"[{self.agent_id}] High failure rate detected, increasing delay")
                request_delay = min(request_delay * 1.5, 5.0)
        
        # Print summary
        elapsed_time = time.time() - start_time
        print(f"\n{'='*60}")
        print(f"Test cycle complete for {self.agent_id}")
        print(f"{'='*60}")
        print(f"Total requests: {self.requests_made}")
        print(f"Successful: {successful_requests}")
        print(f"Rate limited: {self.requests_rate_limited}")
        print(f"Success rate: {successful_requests / self.requests_made * 100:.1f}%")
        print(f"Total time: {elapsed_time:.1f}s")
        print(f"Time spent waiting (rate limit): {self.total_wait_time:.1f}s")
        print(f"Effective request rate: {successful_requests / elapsed_time:.2f} req/s")
        print(f"{'='*60}\n")


def main():
    """Demonstrate proper rate limit handling."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Well-behaved test agent example")
    parser.add_argument("--agent-id", default="test-agent-1", help="Agent identifier")
    parser.add_argument("--api-base", default="http://localhost:8443", help="API base URL")
    parser.add_argument("--requests", type=int, default=50, help="Number of requests to make")
    parser.add_argument("--delay", type=float, default=0.5, help="Base delay between requests")
    
    args = parser.parse_args()
    
    # Create and run the agent
    agent = WellBehavedTestAgent(args.agent_id, args.api_base)
    agent.run_test_cycle(args.requests, args.delay)


if __name__ == "__main__":
    main()