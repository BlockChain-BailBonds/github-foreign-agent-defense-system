from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path
import yaml
from .client import request
from .guardian import Guardian, GuardianError
from .ledger import EvidenceLedger, LedgerError
from .sandbox import SandboxError, doctor
from .util import sha256_file

def manifest_init(a):
    exe=Path(a.executable).resolve()
    if not exe.is_file(): print(f'not a file: {exe}',file=sys.stderr); return 2
    data={'version':1,'agent_id':a.agent_id,'identity':{'executable':str(exe),'executable_sha256':sha256_file(exe),'model':str(Path(a.model).resolve()) if a.model else None,'model_sha256':sha256_file(a.model) if a.model else None,'artifacts':[{'path':str(Path(x).resolve()),'sha256':sha256_file(x)} for x in a.artifact]},'sandbox':{'workspace':str(Path(a.workspace).resolve()),'scratch':str(Path(a.scratch).resolve()),'run_as_uid':a.run_as_uid,'readonly_binds':[]},'allowed':{'read_workspace':True,'write_project':True,'execute':True,'spawn_process':True,'network':False,'credentials':False,'external_tools':False},'allowed_executables':[str(exe)],'heartbeat_seconds':2,'resource_limits':{'memory_max':1073741824,'tasks_max':128,'cpu_quota_percent':200}}
    Path(a.out).write_text(yaml.safe_dump(data,sort_keys=False),'utf-8'); print(a.out); return 0

def run_guardian(a):
    argv=a.agent_command[1:] if a.agent_command and a.agent_command[0]=='--' else a.agent_command
    try: return Guardian(a.manifest,a.policy,a.state_dir).run(argv)
    except (GuardianError,SandboxError,OSError,ValueError) as exc: print(f'FADS REFUSED TO START: {exc}',file=sys.stderr); return 2

def verify(a):
    key=os.environ.get('FADS_LEDGER_HMAC_KEY')
    try: result=EvidenceLedger(Path(a.state_dir)/'evidence',key.encode() if key else None).verify()
    except LedgerError as exc: print(f'INVALID: {exc}',file=sys.stderr); return 2
    print(json.dumps(result,indent=2,sort_keys=True)); return 0

def build_parser():
    p=argparse.ArgumentParser(prog='fads'); s=p.add_subparsers(dest='cmd',required=True)
    d=s.add_parser('doctor'); d.set_defaults(func=lambda a:(print(json.dumps(doctor(),indent=2,sort_keys=True)) or (0 if doctor()['ready'] else 2)))
    h=s.add_parser('hash'); h.add_argument('file'); h.set_defaults(func=lambda a:(print(sha256_file(a.file)) or 0))
    m=s.add_parser('manifest-init'); m.add_argument('--agent-id',required=True); m.add_argument('--executable',required=True); m.add_argument('--model'); m.add_argument('--artifact',action='append',default=[]); m.add_argument('--workspace',required=True); m.add_argument('--scratch',required=True); m.add_argument('--run-as-uid',type=int,required=True); m.add_argument('--out',required=True); m.set_defaults(func=manifest_init)
    r=s.add_parser('run'); r.add_argument('--manifest',required=True); r.add_argument('--policy',default='policy.yaml'); r.add_argument('--state-dir',default='/var/lib/fads'); r.add_argument('agent_command',nargs=argparse.REMAINDER); r.set_defaults(func=run_guardian)
    v=s.add_parser('verify-ledger'); v.add_argument('--state-dir',default='/var/lib/fads'); v.set_defaults(func=verify)
    return p

def main():
    a=build_parser().parse_args(); return int(a.func(a))
if __name__=='__main__': raise SystemExit(main())
