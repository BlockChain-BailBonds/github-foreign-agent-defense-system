import pytest
from pathlib import Path
from fads.securefs import WorkspaceFS

def test_inside_workspace(tmp_path: Path):
    f=WorkspaceFS(tmp_path/'ws'); f.write_bytes('hello.txt',b'hello'); assert f.read_bytes('hello.txt')==b'hello'

def test_escape_rejected(tmp_path: Path):
    f=WorkspaceFS(tmp_path/'ws')
    with pytest.raises(ValueError): f.write_bytes('../escape.txt',b'no')
    with pytest.raises(ValueError): f.read_bytes('/etc/passwd')

def test_symlink_rejected(tmp_path: Path):
    root=tmp_path/'ws'; root.mkdir(); (root/'link').symlink_to('/etc/passwd'); f=WorkspaceFS(root)
    with pytest.raises(OSError): f.read_bytes('link')
