from pathlib import Path
from fads.sandbox import LinuxSandbox

def test_minimal_mount_plan(tmp_path: Path, monkeypatch):
    ws=tmp_path/'ws'; ws.mkdir(); sc=tmp_path/'scratch'; sc.mkdir(); run=tmp_path/'run'; run.mkdir(); m={'identity':{'executable':'/usr/bin/python3'},'sandbox':{'workspace':str(ws),'scratch':str(sc),'run_as_uid':1000},'allowed_executables':['/usr/bin/python3'],'resource_limits':{}}
    monkeypatch.setattr('fads.sandbox._which',lambda n:f'/usr/bin/{n}'); sb=LinuxSandbox(m,{'sandbox':{}},'abc',run); cmd=sb._bwrap(False); assert '--unshare-net' in cmd and '--cap-drop' in cmd and str(ws) in cmd and '/workspace' in cmd
