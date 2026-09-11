import pytest
from pathlib import Path
from fads.identity import IdentityError, verify_manifest_identity
from fads.util import sha256_file

def test_identity_hash(tmp_path: Path):
    exe=tmp_path/'agent'; exe.write_text('agent'); m={'identity':{'executable':str(exe),'executable_sha256':sha256_file(exe),'model':None,'model_sha256':None,'artifacts':[]}}; assert verify_manifest_identity(m)['executable_sha256']==sha256_file(exe)

def test_identity_mismatch(tmp_path: Path):
    exe=tmp_path/'agent'; exe.write_text('agent'); m={'identity':{'executable':str(exe),'executable_sha256':'0'*64,'model':None,'model_sha256':None,'artifacts':[]}}
    with pytest.raises(IdentityError): verify_manifest_identity(m)
