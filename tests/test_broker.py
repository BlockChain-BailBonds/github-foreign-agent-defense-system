import secrets
from pathlib import Path
from types import SimpleNamespace
from fads.broker import CapabilityBroker
from fads.ledger import EvidenceLedger
from fads.policy import PolicyEngine
from fads.types import Session, TrustState

class FakeSandbox:
    def run_oneshot(self, argv, workspace_writable, timeout): return SimpleNamespace(returncode=0,stdout='ok\n',stderr='')

def make(tmp_path):
    states={s:{'read_workspace':True,'write_project':s=='trusted','execute':s=='trusted','spawn_process':s=='trusted','network':False,'credentials':False,'external_tools':False} for s in ('trusted','restricted','quarantined')}; states['terminated']={k:False for k in states['trusted']}
    p={'states':states,'responses':{'unauthorized_network_request':'restricted','session_replay':'quarantined','unauthorized_executable':'quarantined'}}; m={'allowed':{'read_workspace':True,'write_project':True,'execute':True,'spawn_process':True,'network':False,'credentials':False,'external_tools':False},'allowed_executables':['/usr/bin/python3'],'sandbox':{'run_as_uid':1000}}
    sid=secrets.token_hex(8); ws=tmp_path/'ws'; ws.mkdir(); s=Session('a',sid,tmp_path/'m','x',tmp_path/'p','y',ws,tmp_path/'scratch',tmp_path/'run',tmp_path/'run'/'broker.sock',2)
    return CapabilityBroker(s,PolicyEngine(p,m),m,EvidenceLedger(tmp_path/'ev'),FakeSandbox(),lambda pid:True),s

def test_write_then_revoke(tmp_path: Path):
    b,s=make(tmp_path); assert b.handle({'session':s.session_id,'op':'write','path':'a.txt','content':'x'},123)['ok']; assert not b.handle({'session':s.session_id,'op':'network'},123)['ok']; assert s.state==TrustState.RESTRICTED; assert not b.handle({'session':s.session_id,'op':'write','path':'b.txt','content':'y'},123)['ok']; assert not (s.workspace/'b.txt').exists()

def test_heartbeat_replay_quarantines(tmp_path: Path):
    b,s=make(tmp_path); assert b.handle({'session':s.session_id,'op':'heartbeat','counter':1},123)['ok']; assert not b.handle({'session':s.session_id,'op':'heartbeat','counter':1},123)['ok']; assert s.state==TrustState.QUARANTINED
