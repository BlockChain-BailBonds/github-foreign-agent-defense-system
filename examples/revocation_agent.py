from __future__ import annotations
import json, os, socket, time
SOCK=os.environ['FADS_BROKER_SOCKET']; SESSION=os.environ['FADS_SESSION_ID']
def call(payload):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.connect(SOCK); s.sendall((json.dumps({'session':SESSION,**payload})+'\n').encode()); data=b''
        while b'\n' not in data: data+=s.recv(65536)
    return json.loads(data.split(b'\n',1)[0])
def main():
    direct_write_blocked=False
    try: open('/workspace/direct-write.txt','w').write('must fail')
    except OSError: direct_write_blocked=True
    hb=call({'op':'heartbeat','counter':1}); before=call({'op':'write','path':'before-restriction.txt','content':'allowed\n'})
    direct_network_blocked=False
    try: socket.create_connection(('1.1.1.1',53),timeout=1).close()
    except OSError: direct_network_blocked=True
    net=call({'op':'network'}); after=call({'op':'write','path':'after-restriction.txt','content':'must be denied\n'}); hb2=call({'op':'heartbeat','counter':2})
    report={'direct_write_blocked':direct_write_blocked,'direct_network_blocked':direct_network_blocked,'heartbeat_ok':hb.get('ok') is True and hb2.get('ok') is True,'broker_write_before_allowed':before.get('ok') is True,'network_request_denied':net.get('ok') is False,'state_restricted':net.get('state')=='RESTRICTED','broker_write_after_denied':after.get('ok') is False}
    print(json.dumps(report,sort_keys=True),flush=True); return 0 if all(report.values()) else 1
if __name__=='__main__': raise SystemExit(main())
