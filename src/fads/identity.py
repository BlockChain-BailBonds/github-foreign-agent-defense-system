from __future__ import annotations

from pathlib import Path
from typing import Any
from .util import sha256_file

class IdentityError(RuntimeError):
    pass

def verify_manifest_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    identity = manifest['identity']
    executable = Path(identity['executable']).resolve()
    if not executable.is_file():
        raise IdentityError(f'approved executable does not exist: {executable}')
    expected = str(identity['executable_sha256']).removeprefix('sha256:').lower()
    actual = sha256_file(executable)
    if actual != expected:
        raise IdentityError(f'executable hash mismatch for {executable}')
    model_actual = None
    if identity.get('model') or identity.get('model_sha256'):
        if not identity.get('model') or not identity.get('model_sha256'):
            raise IdentityError('model and model_sha256 must be supplied together')
        model = Path(identity['model']).resolve()
        if not model.is_file():
            raise IdentityError(f'approved model does not exist: {model}')
        model_actual = sha256_file(model)
        if model_actual != str(identity['model_sha256']).removeprefix('sha256:').lower():
            raise IdentityError(f'model hash mismatch for {model}')
    verified = []
    for item in identity.get('artifacts', []) or []:
        if not isinstance(item, dict) or not item.get('path') or not item.get('sha256'):
            raise IdentityError('identity.artifacts entries require path and sha256')
        artifact = Path(item['path']).resolve()
        if not artifact.is_file():
            raise IdentityError(f'identity artifact does not exist: {artifact}')
        digest = sha256_file(artifact)
        if digest != str(item['sha256']).removeprefix('sha256:').lower():
            raise IdentityError(f'identity artifact hash mismatch for {artifact}')
        verified.append({'path': str(artifact), 'sha256': digest})
    return {'executable': str(executable), 'executable_sha256': actual, 'model_sha256': model_actual, 'artifacts': verified}
