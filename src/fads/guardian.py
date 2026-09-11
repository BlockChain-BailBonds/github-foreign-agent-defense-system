from __future__ import annotations
import os, secrets, time
from pathlib import Path
from .broker import CapabilityBroker
from .config import load_manifest, load_policy
from .identity import IdentityError, verify_manifest_identity
from .ledger import EvidenceLedger
from .policy import PolicyEngine
from .sandbox import LinuxSandbox
from .types import Session, TrustState
from .util import ensure_private_dir, sha256_file

class GuardianError(RuntimeError): pass

class Guardian:
    def __init__(self, manifest_path, policy_path, state_dir):
        self.manifest,mhash,mpath=load_manifest(manifest_path); self.policy_doc,phash,ppath=load_policy(policy_path); self.policy=PolicyEngine(self.policy_doc,self.manifest)
        self.state_dir=Path(state_dir).resolve(); ensure_private_dir(self.state_dir); self.evidence_dir=self.state_dir/'evidence'; self.runtime_root=self.state_dir/'run'; ensure_private_dir(self.evidence_dir); ensure_private_dir(self.runtime_root,0o755)
        sid=secrets.token_hex(16); runtime=self.runtime_root/sid; ensure_private_dir(runtime,0o755); workspace=Path(self.manifest['sandbox']['workspace']).resolve(); scratch=Path(self.manifest['sandbox'].get('scratch') or workspace.parent/'.fads-scratch').resolve(); workspace.mkdir(parents=True,exist_ok=True); scratch.mkdir(parents=True,exist_ok=True)
        self.session=Session(self.manifest['agent_id'],sid,mpath,mhash,ppath,phash,workspace,scratch,runtime,runtime/'broker.sock',float(self.manifest.get('heartbeat_seconds',2)))
        key=os.environ.get('FADS_LEDGER_HMAC_KEY'); self.ledger=EvidenceLedger(self.evidence_dir,key.encode() if key else None); self.sandbox=LinuxSandbox(self.manifest,self.policy_doc,sid,runtime)
        self.broker=CapabilityBroker(self.session,self.policy,self.manifest,self.ledger,self.sandbox,self.sandbox.pid_in_unit,int(self.policy_doc.get('runtime',{}).get('max_request_bytes',1048576)))
    def _transition(self,event,reason):
        state=self.broker.transition(event,reason)
        if state>=TrustState.QUARANTINED: self.sandbox.stop()
    def preflight(self):
        self.sandbox.require_ready()
        try: return verify_manifest_identity(self.manifest)
        except IdentityError as exc: self._transition('identity_hash_mismatch',str(exc)); raise GuardianError(str(exc)) from exc
    def _integrity(self):
        if sha256_file(self.session.policy_path)!=self.session.policy_sha256: self._transition('policy_tamper','policy changed during active session'); return False
        if sha256_file(self.session.manifest_path)!=self.session.manifest_sha256: self._transition('manifest_tamper','manifest changed during active session'); return False
        try: verify_manifest_identity(self.manifest)
        except IdentityError as exc: self._transition('identity_hash_mismatch',str(exc)); return False
        return True
    def run(self,argv):
        if not argv: raise GuardianError('agent command is required')
        if not argv[0].startswith('/'): raise GuardianError('agent command must use an absolute executable path')
        if Path(argv[0]).resolve()!=Path(self.manifest['identity']['executable']).resolve(): raise GuardianError('launch executable is not the manifest identity')
        identity=self.preflight(); self.broker.start()
        try:
            unit,pid=self.sandbox.launch(argv); self.session.unit_name=unit; self.session.main_pid=pid; self.session.last_heartbeat_monotonic=time.monotonic(); self.ledger.append({'agent':self.session.agent_id,'session':self.session.session_id,'pid':pid,'event':'SESSION_STARTED','state':self.session.state.name,'unit':unit,'identity':identity}); print(f'FADS session={self.session.session_id} state={self.session.state.name} unit={unit}',flush=True)
            rt=self.policy_doc.get('runtime',{}); interval=float(rt.get('monitor_interval_seconds',1)); deadline=self.session.heartbeat_seconds*int(rt.get('missed_heartbeat_limit',3)); seen=set()
            while self.sandbox.is_active():
                if not self._integrity(): break
                elapsed=time.monotonic()-self.session.last_heartbeat_monotonic
                if elapsed>deadline and self.session.state==TrustState.TRUSTED: self._transition('missed_heartbeats',f'no valid heartbeat for {elapsed:.2f}s')
                for item in self.sandbox.unauthorized_processes():
                    key=(item['pid'],item['exe'])
                    if key not in seen: seen.add(key); self._transition('foreign_process',f"unapproved executable in session cgroup: {item['exe']} pid={item['pid']}")
                if self.session.state>=TrustState.QUARANTINED: break
                time.sleep(interval)
            self.ledger.append({'agent':self.session.agent_id,'session':self.session.session_id,'event':'SESSION_ENDED','state':self.session.state.name,'unit':self.session.unit_name}); return 0 if self.session.state==TrustState.TRUSTED else 2
        finally:
            self.sandbox.stop(); self.broker.stop(); self.ledger.verify()
