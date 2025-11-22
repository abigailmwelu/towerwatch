"""
Rate limiting module for TowerWatch security system.

This module provides rate limiting functionality using Redis for distributed tracking.
It supports different rate limiting strategies and can be used as a decorator or middleware.
"""
import time
from functools import wraps
from typing import Callable, Optional, Union, Dict, Any
import redis
from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.apps import apps

# Rate limit configurations
DEFAULT_RATE_LIMITS = {
    'default': {'requests': 100, 'window': 60},  # 100 requests per minute
    'login': {'requests': 5, 'window': 60},     # 5 login attempts per minute
    'api': {'requests': 1000, 'window': 3600},  # 1000 API requests per hour
    'sensitive': {'requests': 10, 'window': 300},  # 10 sensitive operations per 5 minutes
}

class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    def __init__(self, message: str, retry_after: int):
        self.message = message
        self.retry_after = retry_after
        super().__init__(self.message)

class RateLimiter:
    """Rate limiter using Redis for distributed rate limiting."""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        """Initialize rate limiter with optional Redis client."""
        self.redis = redis_client or self._get_redis_client()
        self.rate_limits = getattr(settings, 'RATE_LIMITS', DEFAULT_RATE_LIMITS)
    
    def _get_redis_client(self) -> redis.Redis:
        """Get Redis client with settings from Django settings."""
        try:
            return redis.Redis(
                host=getattr(settings, 'REDIS_HOST', 'localhost'),
                port=getattr(settings, 'REDIS_PORT', 6379),
                db=getattr(settings, 'RATE_LIMIT_REDIS_DB', 0),
                decode_responses=True
            )
        except Exception as e:
            # Fallback to Django cache if Redis is not available
            return None
    
    def get_client_identifier(self, request: HttpRequest) -> str:
        """Get unique identifier for rate limiting (IP + user agent)."""
        ip = request.META.get('HTTP_X_FORWARDED_FOR')
        if ip:
            ip = ip.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        return f"{ip}:{hash(user_agent)}"
    
    def get_rate_limit_key(self, identifier: str, scope: str) -> str:
        """Generate Redis key for rate limiting."""
        return f"rate_limit:{scope}:{identifier}"
    
    def is_rate_limited(
        self,
        identifier: str,
        scope: str = 'default',
        requests: Optional[int] = None,
        window: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Check if the request exceeds the rate limit.
        
        Args:
            identifier: Unique identifier for the client
            scope: Rate limit scope (e.g., 'api', 'login')
            requests: Maximum number of requests allowed in the time window
            window: Time window in seconds
            
        Returns:
            Dict with rate limiting information
        """
        if not self.redis:
            # If Redis is not available, skip rate limiting
            return {'is_limited': False, 'remaining': float('inf'), 'limit': 0, 'reset': 0}
        
        # Get rate limit configuration
        config = self.rate_limits.get(scope, self.rate_limits['default'])
        max_requests = requests or config['requests']
        time_window = window or config['window']
        
        # Generate Redis key
        key = self.get_rate_limit_key(identifier, scope)
        
        # Use Redis pipeline for atomic operations
        with self.redis.pipeline() as pipe:
            try:
                pipe.incr(key)
                current_time = int(time.time())
                pipe.expire(key, time_window)
                count = pipe.execute()[0]
                
                # Calculate remaining requests and reset time
                remaining = max(0, max_requests - count)
                reset_time = current_time + time_window
                
                return {
                    'is_limited': count > max_requests,
                    'remaining': remaining,
                    'limit': max_requests,
                    'reset': reset_time
                }
                
            except redis.RedisError as e:
                # Log error and fail open (don't block if Redis is down)
                import logging
                logger = logging.getLogger(__name__)
                logger.error(f"Redis error in rate limiting: {str(e)}")
                return {'is_limited': False, 'remaining': float('inf'), 'limit': 0, 'reset': 0}
    
    def rate_limit(
        self,
        scope: str = 'default',
        requests: Optional[int] = None,
        window: Optional[int] = None,
        block: bool = True
    ) -> Callable:
        """
        Decorator for rate limiting views.
        
        Args:
            scope: Rate limit scope
            requests: Max requests per window
            window: Time window in seconds
            block: Whether to block requests that exceed the limit
            
        Returns:
            Decorated view function
        """
        def decorator(view_func: Callable) -> Callable:
            @wraps(view_func)
            def _wrapped_view(request: HttpRequest, *args, **kwargs):
                # Skip rate limiting for superusers if configured
                if getattr(settings, 'RATE_LIMIT_EXEMPT_SUPERUSERS', False) and \
                   hasattr(request, 'user') and request.user.is_superuser:
                    return view_func(request, *args, **kwargs)
                
                # Get client identifier
                identifier = self.get_client_identifier(request)
                
                # Check rate limit
                rate_info = self.is_rate_limited(identifier, scope, requests, window)
                
                # Add rate limit headers to response
                response_headers = {
                    'X-RateLimit-Limit': str(rate_info['limit']),
                    'X-RateLimit-Remaining': str(rate_info['remaining']),
                    'X-RateLimit-Reset': str(rate_info['reset']),
                }
                
                if rate_info['is_limited'] and block:
                    # Log the rate limit event
                    self.log_prevention(identifier.split(':')[0], 'rate_limit', f"Rate limit exceeded for scope '{scope}'")
                    
                    # Return 429 Too Many Requests
                    response = JsonResponse(
                        {
                            'error': 'rate_limit_exceeded',
                            'message': 'Too many requests. Please try again later.',
                            'retry_after': rate_info['reset'] - int(time.time())
                        },
                        status=429
                    )
                    
                    # Add headers
                    for key, value in response_headers.items():
                        response[key] = value
                    
                    return response
                
                # Call the view function
                response = view_func(request, *args, **kwargs)
                
                # Add rate limit headers to the response
                for key, value in response_headers.items():
                    response[key] = value
                
                return response
            
            return _wrapped_view
        return decorator

# Global rate limiter instance
rate_limiter = RateLimiter()

# Decorator for convenience
rate_limit = rate_limiter.rate_limit