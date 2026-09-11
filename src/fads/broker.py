from __future__ import annotations
import json, os, socket, socketserver, struct, threading, time
from pathlib import Path
from .securefs import WorkspaceFS
from .types import TrustState

class CapabilityBroker:
    def __init__(self, session, policy, manifest, ledger, sandbox, peer_validator, max_request_bytes=1048576):
        self.session=session; self.policy=policy; self.manifest=manifest; self.ledger=ledger; self.sandbox=sandbox; self.peer_validator=peer_validator; self.max_request_bytes=max_request_bytes; self.fs=WorkspaceFS(session.workspace); self._server=None; self._thread=None; self._lock=threading.Lock()
    def set_state(self,state,reason,event):
        with self._lock:
            old=self.session.state
            if state<old: return
            self.session.state=state
            if state!=old: self.ledger.append({'agent':self.session.agent_id,'session':self.session.session_id,'event':event,'previous_state':old.name,'new_state':state.name,'reason':reason,'action':'CAPABILITIES_REEVALUATED'})
    def transition(self,event,reason):
        target,_=self.policy.transition(event,self.session.state); self.set_state(target,reason,event.upper()); return self.session.state
    def _deny(self,capability,reason,request):
        self.ledger.append({'agent':self.session.agent_id,'session':self.session.session_id,'event':'CAPABILITY_DENIED','state':self.session.state.name,'capability':capability,'reason':reason,'operation':request.get('op')}); return {'ok':False,'error':reason,'state':self.session.state.name}
    def _allowed(self,c): return self.policy.capability_allowed(self.session.state,c)
    def handle(self,request,peer_pid):
        if not self.peer_validator(peer_pid):
            self.ledger.append({'agent':self.session.agent_id,'session':self.session.session_id,'event':'FOREIGN_BROKER_PEER','peer_pid':peer_pid,'action':'DENIED'}); return {'ok':False,'error':'peer is outside authorized session cgroup','state':self.session.state.name}
        if request.get('session')!=self.session.session_id:
            self.transition('session_replay','invalid or replayed session identifier from authorized peer'); return self._deny('session','invalid session',request)
        op=request.get('op')
        if op=='heartbeat':
            counter=request.get('counter')
            if not isinstance(counter,int) or counter<=self.session.last_counter:
                self.transition('session_replay','heartbeat counter replay or reordering'); return self._deny('heartbeat','heartbeat counter must strictly increase',request)
            self.session.last_counter=counter; self.session.last_heartbeat_monotonic=time.monotonic(); return {'ok':True,'state':self.session.state.name,'counter':counter}
        if op=='status': return {'ok':True,'agent':self.session.agent_id,'session':self.session.session_id,'state':self.session.state.name}
        if op=='read':
            if not self._allowed('read_workspace'): return self._deny('read_workspace','read capability revoked',request)
            try: return {'ok':True,'state':self.session.state.name,'content':self.fs.read_bytes(str(request.get('path',''))).decode('utf-8')}
            except Exception as exc: return self._deny('read_workspace',f'read rejected: {exc}',request)
        if op=='write':
            if not self._allowed('write_project'): return self._deny('write_project','write capability revoked',request)
            content=request.get('content')
            if not isinstance(content,str): return self._deny('write_project','content must be UTF-8 text',request)
            try:
                self.fs.write_bytes(str(request.get('path','')),content.encode()); self.ledger.append({'agent':self.session.agent_id,'session':self.session.session_id,'event':'CAPABILITY_USED','state':self.session.state.name,'capability':'write_project','path':request.get('path')}); return {'ok':True,'state':self.session.state.name}
            except Exception as exc: return self._deny('write_project',f'write rejected: {exc}',request)
        if op=='exec':
            if not self._allowed('execute'): return self._deny('execute','execute capability revoked',request)
            argv=request.get('argv')
            if not isinstance(argv,list) or not argv or not all(isinstance(v,str) and v for v in argv): return self._deny('execute','invalid argv',request)
            resolved=str(Path(argv[0]).resolve()) if argv[0].startswith('/') else ''
            allowed={str(Path(v).resolve()) for v in self.manifest.get('allowed_executables',[])}
            if resolved not in allowed:
                self.transition('unauthorized_executable',f'executable is not approved: {resolved}'); return self._deny('execute','executable not approved',request)
            timeout=request.get('timeout',30)
            if not isinstance(timeout,int) or timeout<1 or timeout>120: return self._deny('execute','timeout must be 1..120 seconds',request)
            result=self.sandbox.run_oneshot([resolved,*argv[1:]],self._allowed('write_project'),timeout)
            return {'ok':result.returncode==0,'state':self.session.state.name,'returncode':result.returncode,'stdout':result.stdout[-65536:],'stderr':result.stderr[-65536:]}
        if op=='network':
            self.transition('unauthorized_network_request','network broker is disabled in v0.1'); return self._deny('network','network capability unavailable',request)
        return self._deny('unknown',f'unknown operation: {op}',request)
    def start(self):
        path=self.session.broker_socket; path.parent.mkdir(parents=True,exist_ok=True)
        try: path.unlink()
        except FileNotFoundError: pass
        broker=self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                peer_pid,_,_=struct.unpack('3i',self.request.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)); raw=self.rfile.readline(broker.max_request_bytes+1)
                try:
                    payload=json.loads(raw); response=broker.handle(payload,peer_pid) if isinstance(payload,dict) else {'ok':False,'error':'request must be object'}
                except Exception as exc: response={'ok':False,'error':f'invalid request: {exc}'}
                self.wfile.write((json.dumps(response,separators=(',',':'))+'\n').encode())
        class Server(socketserver.ThreadingUnixStreamServer): daemon_threads=True
        self._server=Server(str(path),Handler); uid=int(self.manifest['sandbox']['run_as_uid']); os.chown(path,uid,-1); os.chmod(path,0o600); self._thread=threading.Thread(target=self._server.serve_forever,daemon=True); self._thread.start()
    def stop(self):
        if self._server: self._server.shutdown(); self._server.server_close(); self._server=None
        try: self.session.broker_socket.unlink()
        except FileNotFoundError: pass
