"""Original model-free Linux/systemd canary; requires approved cgroup cleanup.

Never run standalone: children intentionally detach or ignore signals. This
file supplies no production/runtime/credential authority and sends no requests.
"""
import os
import signal
import sys
import time


def main():
    if sys.platform!="linux" or len(sys.argv)!=2 or sys.argv[1] not in {"fork-detach","ignore-signals","suspended-child","root-waits"}:
        return 3
    case=sys.argv[1]
    print("case="+case+" root-ready",flush=True)
    if case=="root-waits":
        while True:time.sleep(1)
    child=os.fork()
    if child:
        return 0
    os.setsid()
    if case in {"ignore-signals","suspended-child"}:
        signal.signal(signal.SIGINT,signal.SIG_IGN)
        signal.signal(signal.SIGTERM,signal.SIG_IGN)
    print("case="+case+" detached-child-ready",flush=True)
    if case=="suspended-child":os.kill(os.getpid(),signal.SIGSTOP)
    while True:time.sleep(1)


if __name__=="__main__":raise SystemExit(main())
