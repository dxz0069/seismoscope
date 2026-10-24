"""
缓存系统

提供多级缓存机制，支持：
- 项目扫描缓存
- 漏洞模式缓存
- LLM 调用缓存
- 结果缓存
"""

import hashlib
import json
import time
from typing import Any, Dict, Optional
from pathlib import Path
import logging


logger = logging.getLogger(__name__)


class CacheEntry:
    """缓存条目"""

    def __init__(self, key: str, value: Any, ttl: int = 3600):
        self.key = key
        self.value = value
        self.created_at = time.time()
        self.ttl = ttl
        self.access_count = 0

    def is_expired(self) -> bool:
        """检查是否过期"""
        return time.time() - self.created_at > self.ttl

    def access(self) -> Any:
        """访问缓存条目"""
        self.access_count += 1
        return self.value


class MemoryCache:
    """内存缓存"""

    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Optional[Any]:
        """获取缓存值"""
        entry = self._cache.get(key)
        if entry is None:
            self._misses += 1
            return None

        if entry.is_expired():
            del self._cache[key]
            self._misses += 1
            return None

        self._hits += 1
        return entry.access()

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """设置缓存值"""
        # 如果缓存已满，清理过期条目
        if len(self._cache) >= self.max_size:
            self._cleanup()

        ttl = ttl or self.default_ttl
        self._cache[key] = CacheEntry(key, value, ttl)

    def delete(self, key: str) -> bool:
        """删除缓存条目"""
        if key in self._cache:
            del self._cache[key]
            return True
        return False

    def clear(self) -> None:
        """清空缓存"""
        self._cache.clear()
        self._hits = 0
        self._misses = 0

    def _cleanup(self) -> None:
        """清理过期条目"""
        expired_keys = [k for k, v in self._cache.items() if v.is_expired()]
        for key in expired_keys:
            del self._cache[key]

        # 如果还是满了，删除访问次数最少的
        if len(self._cache) >= self.max_size:
            sorted_entries = sorted(
                self._cache.items(),
                key=lambda x: x[1].access_count
            )
            to_remove = len(self._cache) - self.max_size + 100
            for i in range(to_remove):
                del self._cache[sorted_entries[i][0]]

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        total = self._hits + self._misses
        hit_rate = self._hits / total if total > 0 else 0.0
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": hit_rate,
        }


class FileCache:
    """文件缓存"""

    def __init__(self, cache_dir: str = ".cache/vibe-sec", default_ttl: int = 86400):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl

    def _get_cache_path(self, key: str) -> Path:
        """获取缓存文件路径"""
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.json"

    def get(self, key: str) -> Optional[Any]:
        """获取缓存值"""
        cache_path = self._get_cache_path(key)
        if not cache_path.exists():
            return None

        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # 检查是否过期
            if time.time() - data.get('created_at', 0) > data.get('ttl', self.default_ttl):
                cache_path.unlink()
                return None

            return data.get('value')
        except Exception as e:
            logger.warning(f"Failed to read cache file {cache_path}: {e}")
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """设置缓存值"""
        cache_path = self._get_cache_path(key)
        ttl = ttl or self.default_ttl

        try:
            data = {
                'key': key,
                'value': value,
                'created_at': time.time(),
                'ttl': ttl,
            }
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"Failed to write cache file {cache_path}: {e}")

    def delete(self, key: str) -> bool:
        """删除缓存条目"""
        cache_path = self._get_cache_path(key)
        if cache_path.exists():
            cache_path.unlink()
            return True
        return False

    def clear(self) -> None:
        """清空缓存"""
        for cache_file in self.cache_dir.glob('*.json'):
            cache_file.unlink()


class MultiLevelCache:
    """多级缓存"""

    def __init__(self, memory_cache: MemoryCache = None, file_cache: FileCache = None):
        self.memory_cache = memory_cache or MemoryCache()
        self.file_cache = file_cache or FileCache()

    def get(self, key: str) -> Optional[Any]:
        """获取缓存值（先查内存，再查文件）"""
        # 先查内存缓存
        value = self.memory_cache.get(key)
        if value is not None:
            return value

        # 再查文件缓存
        value = self.file_cache.get(key)
        if value is not None:
            # 写入内存缓存
            self.memory_cache.set(key, value)
            return value

        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """设置缓存值（同时写入内存和文件）"""
        self.memory_cache.set(key, value, ttl)
        self.file_cache.set(key, value, ttl)

    def delete(self, key: str) -> bool:
        """删除缓存条目"""
        memory_deleted = self.memory_cache.delete(key)
        file_deleted = self.file_cache.delete(key)
        return memory_deleted or file_deleted

    def clear(self) -> None:
        """清空缓存"""
        self.memory_cache.clear()
        self.file_cache.clear()

    def get_stats(self) -> Dict[str, Any]:
        """获取缓存统计"""
        return {
            "memory": self.memory_cache.get_stats(),
        }


# 全局缓存实例
cache = MultiLevelCache()


def cached(ttl: int = 3600):
    """缓存装饰器"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # 生成缓存 key
            key_data = {
                'func': func.__name__,
                'args': args,
                'kwargs': kwargs,
            }
            key = hashlib.md5(json.dumps(key_data, sort_keys=True).encode()).hexdigest()

            # 尝试从缓存获取
            cached_value = cache.get(key)
            if cached_value is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return cached_value

            # 执行函数
            result = await func(*args, **kwargs)

            # 写入缓存
            cache.set(key, result, ttl)
            logger.debug(f"Cache miss for {func.__name__}, cached for {ttl}s")

            return result
        return wrapper
    return decorator
