from __future__ import annotations
import os, secrets
from pathlib import Path
from .util import normalize_relpath
NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)
class WorkspaceFS:
    def __init__(self, root): self.root = Path(root).resolve(); self.root.mkdir(parents=True, exist_ok=True)
    def _parent(self, parts):
        rootfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY); fd = rootfd
        try:
            for part in parts[:-1]:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW, dir_fd=fd)
                if fd != rootfd: os.close(fd)
                fd = nxt
            if fd == rootfd: rootfd = -1
            return fd, parts[-1]
        finally:
            if rootfd >= 0: os.close(rootfd)
    def read_bytes(self, relative, max_bytes=4194304):
        parts = normalize_relpath(relative); parent, name = self._parent(parts)
        try:
            fd = os.open(name, os.O_RDONLY | NOFOLLOW, dir_fd=parent)
            try:
                data = os.read(fd, max_bytes + 1)
                if len(data) > max_bytes: raise ValueError('file exceeds broker read limit')
                return data
            finally: os.close(fd)
        finally: os.close(parent)
    def write_bytes(self, relative, data: bytes):
        parts = normalize_relpath(relative); parent, name = self._parent(parts); tmp = f'.fads-{secrets.token_hex(8)}.tmp'; fd = None
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=parent); view = memoryview(data)
            while view: view = view[os.write(fd, view):]
            os.fsync(fd); os.close(fd); fd = None; os.replace(tmp, name, src_dir_fd=parent, dst_dir_fd=parent); os.fsync(parent)
        finally:
            if fd is not None: os.close(fd)
            try: os.unlink(tmp, dir_fd=parent)
            except FileNotFoundError: pass
            os.close(parent)
