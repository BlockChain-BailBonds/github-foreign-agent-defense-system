from __future__ import annotations

import os, pwd, shutil, subprocess, sys, time, uuid
from pathlib import Path
from typing import Any

class SandboxError(RuntimeError): pass

def _which(name: str) -> str | None: return shutil.which(name)

def doctor() -> dict[str, Any]:
    checks = {
        'linux': sys.platform.startswith('linux'),
        'guardian_privileged': hasattr(os, 'geteuid') and os.geteuid() == 0,
        'bwrap': bool(_which('bwrap')),
        'systemd_run': bool(_which('systemd-run')),
        'systemctl': bool(_which('systemctl')),
        'systemd_booted': Path('/run/systemd/system').is_dir(),
        'cgroup_v2': Path('/sys/fs/cgroup/cgroup.controllers').is_file(),
    }
    checks['ready'] = all(checks.values()); return checks

class LinuxSandbox:
    def __init__(self, manifest, policy, session_id: str, runtime_dir: Path):
        self.manifest=manifest; self.policy=policy; self.session_id=session_id; self.runtime_dir=runtime_dir.resolve(); self.unit_name=None; self.control_group=None
    @property
    def workspace(self): return Path(self.manifest['sandbox']['workspace']).resolve()
    @property
    def scratch(self): return Path(self.manifest['sandbox'].get('scratch') or (self.workspace.parent/'.fads-scratch')).resolve()
    def require_ready(self):
        c=doctor()
        if not c['ready']: raise SandboxError('hard sandbox prerequisites missing: '+', '.join(k for k,v in c.items() if k!='ready' and not v))
        uid=self.manifest.get('sandbox',{}).get('run_as_uid')
        try:
            uid=int(uid)
            if uid==0: raise SandboxError('sandbox.run_as_uid=0 is forbidden')
            pwd.getpwuid(uid)
        except (TypeError,ValueError,KeyError) as exc: raise SandboxError(f'invalid sandbox.run_as_uid: {uid}') from exc
    def _bwrap(self, writable=False):
        bwrap=_which('bwrap')
        if not bwrap: raise SandboxError('bwrap is unavailable')
        cmd=[bwrap,'--die-with-parent','--new-session','--unshare-user','--unshare-pid','--unshare-net','--unshare-ipc','--unshare-uts','--unshare-cgroup-try','--cap-drop','ALL','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','HOME','/scratch','--setenv','TMPDIR','/tmp','--setenv','FADS_SESSION_ID',self.session_id,'--setenv','FADS_BROKER_SOCKET','/run/fads/broker.sock','--proc','/proc','--dev','/dev','--tmpfs','/tmp']
        for d in ('/run','/run/fads','/workspace','/scratch','/usr','/usr/bin','/usr/lib','/usr/share','/bin','/lib','/lib64','/etc'): cmd += ['--dir',d]
        for root in ('/usr/lib','/usr/share','/lib','/lib64'):
            if Path(root).exists(): cmd += ['--ro-bind',root,root]
        if Path('/etc/ld.so.cache').exists(): cmd += ['--ro-bind','/etc/ld.so.cache','/etc/ld.so.cache']
        targets=set([self.manifest['identity']['executable'],*self.manifest.get('allowed_executables',[])])
        for target in sorted(targets):
            if not isinstance(target,str) or not target.startswith('/'): continue
            source=str(Path(target).resolve())
            if Path(source).is_file(): cmd += ['--ro-bind',source,target]
        cmd += [('--bind' if writable else '--ro-bind'),str(self.workspace),'/workspace','--bind',str(self.scratch),'/scratch','--ro-bind',str(self.runtime_dir),'/run/fads','--chdir','/workspace']
        return cmd
    def _systemd(self, unit, pipe=False, wait=False):
        uid=int(self.manifest['sandbox']['run_as_uid']); limits=self.manifest.get('resource_limits',{}); sb=self.policy.get('sandbox',{})
        memory=int(limits.get('memory_max',sb.get('default_memory_max',1073741824))); tasks=int(limits.get('tasks_max',sb.get('default_tasks_max',128))); cpu=int(limits.get('cpu_quota_percent',sb.get('default_cpu_quota_percent',200)))
        p=['systemd-run','--quiet','--collect',f'--unit={unit}',f'--uid={uid}','--service-type=exec','--property=NoNewPrivileges=yes','--property=PrivateNetwork=yes','--property=PrivateDevices=yes','--property=ProtectKernelTunables=yes','--property=ProtectKernelModules=yes','--property=ProtectKernelLogs=yes','--property=ProtectControlGroups=yes','--property=RestrictSUIDSGID=yes','--property=LockPersonality=yes','--property=RestrictRealtime=yes','--property=SystemCallArchitectures=native','--property=SystemCallFilter=~@mount @reboot @raw-io @privileged @debug @obsolete','--property=KillMode=control-group',f'--property=MemoryMax={memory}',f'--property=TasksMax={tasks}',f'--property=CPUQuota={cpu}%']
        if pipe: p.append('--pipe')
        if wait: p.append('--wait')
        return p+['--']
    def launch(self, argv):
        self.require_ready(); self.workspace.mkdir(parents=True,exist_ok=True); self.scratch.mkdir(parents=True,exist_ok=True); uid=int(self.manifest['sandbox']['run_as_uid']); os.chown(self.scratch,uid,-1); os.chmod(self.scratch,0o700)
        unit=f'fads-agent-{self.session_id[:12]}.service'; proc=subprocess.run(self._systemd(unit)+self._bwrap(False)+argv,text=True,capture_output=True,timeout=15)
        if proc.returncode!=0: raise SandboxError(f'systemd-run failed: {(proc.stderr or proc.stdout).strip()}')
        self.unit_name=unit; deadline=time.time()+10; pid=0
        while time.time()<deadline:
            out=subprocess.run(['systemctl','show',unit,'-p','MainPID','--value'],text=True,capture_output=True)
            try: pid=int(out.stdout.strip() or '0')
            except ValueError: pid=0
            if pid>0: break
            time.sleep(.1)
        if pid<=0: self.stop(); raise SandboxError('agent unit started but no MainPID became available')
        cg=subprocess.run(['systemctl','show',unit,'-p','ControlGroup','--value'],text=True,capture_output=True)
        if cg.returncode!=0 or not cg.stdout.strip().startswith('/'): self.stop(); raise SandboxError('cannot resolve agent cgroup')
        self.control_group=cg.stdout.strip(); return unit,pid
    def run_oneshot(self, argv, workspace_writable, timeout=30):
        self.require_ready(); unit=f'fads-op-{self.session_id[:8]}-{uuid.uuid4().hex[:8]}.service'
        return subprocess.run(self._systemd(unit,True,True)+self._bwrap(workspace_writable)+argv,text=True,capture_output=True,timeout=timeout)
    def is_active(self): return bool(self.unit_name) and subprocess.run(['systemctl','is-active','--quiet',self.unit_name]).returncode==0
    def stop(self):
        if self.unit_name: subprocess.run(['systemctl','stop',self.unit_name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    def pid_in_unit(self,pid):
        if not self.control_group or pid<=0: return False
        try: text=Path(f'/proc/{pid}/cgroup').read_text('utf-8')
        except OSError: return False
        return any(len(parts:=line.split(':',2))==3 and parts[2].startswith(self.control_group) for line in text.splitlines())
    def pids(self):
        if not self.control_group: return []
        root=Path('/sys/fs/cgroup')/self.control_group.lstrip('/'); values=set()
        for procs in [root/'cgroup.procs',*root.glob('**/cgroup.procs')]:
            try: values.update(int(x) for x in procs.read_text().splitlines())
            except (OSError,ValueError): pass
        return sorted(values)
    def unauthorized_processes(self):
        allowed={str(Path(p).resolve()) for p in self.manifest.get('allowed_executables',[]) if str(p).startswith('/')}; allowed.add(str(Path(self.manifest['identity']['executable']).resolve())); out=[]
        for pid in self.pids():
            try: exe=str(Path(f'/proc/{pid}/exe').resolve())
            except OSError: continue
            if exe not in allowed and not exe.endswith('/bwrap'): out.append({'pid':pid,'exe':exe})
        return out
