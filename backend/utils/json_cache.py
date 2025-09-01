import json
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, Tuple
import os

class JSONFileCache:
    """
    High-performance file-based cache for JSON data with automatic expiration,
    thread safety, and write-through caching for mail applications.
    """
    
    def __init__(self, default_ttl_seconds: int = 300, max_cache_size: int = 1000):
        """
        Initialize the cache manager.
        
        Args:
            default_ttl_seconds: Default time-to-live for cache entries (5 minutes)
            max_cache_size: Maximum number of entries to keep in memory
        """
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._default_ttl = default_ttl_seconds
        self._max_size = max_cache_size
        self._access_times: Dict[str, float] = {}
        
    def _generate_cache_key(self, file_path: str) -> str:
        """Generate a consistent cache key from file path."""
        return str(Path(file_path).resolve())
    
    def _is_expired(self, cache_entry: Dict[str, Any]) -> bool:
        """Check if a cache entry has expired."""
        if 'expires_at' not in cache_entry:
            return True
        return datetime.now() > cache_entry['expires_at']
    
    def _is_file_modified(self, file_path: str, cached_mtime: float) -> bool:
        """Check if file has been modified since caching."""
        try:
            current_mtime = os.path.getmtime(file_path)
            return current_mtime > cached_mtime
        except (OSError, FileNotFoundError):
            return True
    
    def _evict_lru(self):
        """Evict least recently used entries when cache is full."""
        if len(self._cache) <= self._max_size:
            return
            
        # Find the least recently used entry
        lru_key = min(self._access_times.keys(), 
                     key=lambda k: self._access_times.get(k, 0))
        
        with self._lock:
            self._cache.pop(lru_key, None)
            self._access_times.pop(lru_key, None)
    
    def load_json_cached(self, file_path: str, default_value: Any = None, 
                        ttl_seconds: Optional[int] = None) -> Tuple[Any, bool]:
        """
        Load JSON data with caching support.
        
        Args:
            file_path: Path to the JSON file
            default_value: Value to return if file doesn't exist
            ttl_seconds: Custom TTL for this entry (uses default if None)
        
        Returns:
            Tuple of (data, was_cached) where was_cached indicates if data came from cache
        """
        cache_key = self._generate_cache_key(file_path)
        current_time = time.time()
        ttl = ttl_seconds or self._default_ttl
        
        with self._lock:
            # Update access time
            self._access_times[cache_key] = current_time
            
            # Check if we have valid cached data
            if cache_key in self._cache:
                cache_entry = self._cache[cache_key]
                
                # Check expiration and file modification
                if (not self._is_expired(cache_entry) and 
                    not self._is_file_modified(file_path, cache_entry['mtime'])):
                    return cache_entry['data'], True
                else:
                    # Remove expired/stale entry
                    del self._cache[cache_key]
        
        # Cache miss or expired - load from file
        try:
            if not os.path.exists(file_path):
                data = default_value if default_value is not None else []
                
                # Create file with default value if it doesn't exist
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                mtime = os.path.getmtime(file_path)
            else:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                mtime = os.path.getmtime(file_path)
            
            # Cache the loaded data
            with self._lock:
                self._evict_lru()  # Make room if needed
                
                self._cache[cache_key] = {
                    'data': data,
                    'mtime': mtime,
                    'expires_at': datetime.now() + timedelta(seconds=ttl),
                    'cached_at': datetime.now()
                }
                self._access_times[cache_key] = current_time
            
            return data, False
            
        except (json.JSONDecodeError, OSError) as e:
            print(f"Error loading {file_path}: {e}")
            return default_value if default_value is not None else [], False
    
    def save_json_cached(self, file_path: str, data: Any, 
                        ttl_seconds: Optional[int] = None) -> bool:
        """
        Save JSON data with write-through caching.
        
        Args:
            file_path: Path to save the JSON file
            data: Data to save
            ttl_seconds: Custom TTL for this entry
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            # Write to file first (write-through)
            temp_file = file_path + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            # Atomic replace
            os.replace(temp_file, file_path)
            mtime = os.path.getmtime(file_path)
            
            # Update cache
            cache_key = self._generate_cache_key(file_path)
            ttl = ttl_seconds or self._default_ttl
            current_time = time.time()
            
            with self._lock:
                self._evict_lru()  # Make room if needed
                
                self._cache[cache_key] = {
                    'data': data,
                    'mtime': mtime,
                    'expires_at': datetime.now() + timedelta(seconds=ttl),
                    'cached_at': datetime.now()
                }
                self._access_times[cache_key] = current_time
            
            return True
            
        except Exception as e:
            print(f"Error saving {file_path}: {e}")
            return False
    
    def invalidate(self, file_path: str):
        """Manually invalidate a cached entry."""
        cache_key = self._generate_cache_key(file_path)
        with self._lock:
            self._cache.pop(cache_key, None)
            self._access_times.pop(cache_key, None)
    
    def clear_cache(self):
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        with self._lock:
            return {
                'total_entries': len(self._cache),
                'max_size': self._max_size,
                'cache_keys': list(self._cache.keys()),
                'oldest_entry': min(
                    [entry['cached_at'] for entry in self._cache.values()],
                    default=None
                ),
                'memory_usage_estimate_kb': len(str(self._cache)) / 1024
            }


# Global cache instance
_global_cache = JSONFileCache(default_ttl_seconds=300, max_cache_size=1000)

def get_cache_instance() -> JSONFileCache:
    """Get the global cache instance."""
    return _global_cache


# Drop-in replacement functions for your existing code
def load_users_cached():
    """Cached version of load_users() function."""
    from config import USERS_FILE
    return _global_cache.load_json_cached(str(USERS_FILE), default_value={})[0]


def save_users_cached(users):
    """Cached version of save_users() function."""
    from config import USERS_FILE
    return _global_cache.save_json_cached(str(USERS_FILE), users)


def load_companies_cached():
    """Cached version of load_companies() function."""
    from config import DATA_DIR
    companies_file = DATA_DIR / "companies.json"
    return _global_cache.load_json_cached(str(companies_file), default_value={})[0]


def save_companies_cached(companies):
    """Cached version of save_companies() function."""
    from config import DATA_DIR
    companies_file = DATA_DIR / "companies.json"
    return _global_cache.save_json_cached(str(companies_file), companies)


def read_mail_file_cached(email, file_type):
    """Cached version of read_mail_file() function."""
    from config import MAIL_ROOT
    file_path = os.path.join(MAIL_ROOT, email, f'{file_type}.json')
    return _global_cache.load_json_cached(file_path, default_value=[])[0]


def save_mail_file_cached(email, file_type, data):
    """Cached version of save_mail_file() function."""
    from config import MAIL_ROOT
    file_path = os.path.join(MAIL_ROOT, email, f'{file_type}.json')
    return _global_cache.save_json_cached(file_path, data)


# Usage Example for your existing code:
"""
# Replace your existing function calls with cached versions:

# OLD:
users = load_users()
# NEW:
users = load_users_cached()

# OLD:
save_users(users)
# NEW:
save_users_cached(users)

# OLD:
inbox = read_mail_file(email, 'inbox')
# NEW:
inbox = read_mail_file_cached(email, 'inbox')

# OLD:
save_mail_file(email, 'inbox', inbox)
# NEW:
save_mail_file_cached(email, 'inbox', inbox)
"""


# Integration example for your user.py file:
def patch_user_functions():
    """
    Monkey patch existing functions to use caching.
    Call this once at application startup.
    """
    import models.user as user_module
    import models.company as company_module
    import utils.file_helpers as file_helpers_module
    
    # Replace functions with cached versions
    user_module.load_users = load_users_cached
    user_module.save_users = save_users_cached
    company_module.load_companies = load_companies_cached  
    company_module.save_companies = save_companies_cached
    file_helpers_module.read_mail_file = read_mail_file_cached
    file_helpers_module.save_mail_file = save_mail_file_cached
    
    print("✓ JSON file operations patched with caching")


# Performance monitoring decorator
def monitor_performance(func_name: str):
    """Decorator to monitor function performance."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            
            execution_time = (end_time - start_time) * 1000  # Convert to milliseconds
            if execution_time > 100:  # Log slow operations
                print(f"⚡ {func_name}: {execution_time:.2f}ms")
            
            return result
        return wrapper
    return decorator