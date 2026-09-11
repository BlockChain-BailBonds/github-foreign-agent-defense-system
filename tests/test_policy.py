from fads.policy import PolicyEngine
from fads.types import TrustState

def docs():
    p={'states':{'trusted':{'write_project':True,'read_workspace':True},'restricted':{'write_project':False,'read_workspace':True},'quarantined':{'write_project':False,'read_workspace':True},'terminated':{'write_project':False,'read_workspace':False}},'responses':{'foreign_process':'restricted','policy_tamper':'terminated'}}
    m={'allowed':{'write_project':True,'read_workspace':True}}
    return p,m

def test_ceiling_and_state_both_required():
    p,m=docs(); e=PolicyEngine(p,m); assert e.capability_allowed(TrustState.TRUSTED,'write_project'); assert not e.capability_allowed(TrustState.RESTRICTED,'write_project'); m['allowed']['write_project']=False; assert not e.capability_allowed(TrustState.TRUSTED,'write_project')

def test_state_is_monotonic():
    p,m=docs(); e=PolicyEngine(p,m); assert e.response_state('foreign_process',TrustState.TRUSTED)==TrustState.RESTRICTED; assert e.response_state('foreign_process',TrustState.QUARANTINED)==TrustState.QUARANTINED
