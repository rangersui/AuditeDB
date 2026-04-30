"""L3 example — inbox triage agent.

This is the kind of thing that makes elastik a "Python frontend" in the
PyTorch sense. L1 (`e.put`) and L2 (`@listen`, `MoveTo`, `Archive`) are
atoms and modules. This file is a *program* — it composes them with
if/elif into a business rule.

Run as a sidecar (elastik-core fans out to it):

    # 1. start elastik-core with this agent registered as a listener
    ELASTIK_KEY=k ELASTIK_TOKEN=t \
        ELASTIK_LISTENERS="/home/inbox/*=http://localhost:3200/" \
        ./elastik-core

    # 2. start this agent
    python examples/agent_inbox_triage.py

    # 3. push something to the inbox
    curl -X PUT -H "Authorization: Bearer t" \
        -H "X-Meta-Subject: URGENT outage" \
        http://localhost:3105/home/inbox/ranger/abc \
        -d "the prod db is down"

    # → agent fires, sees "URGENT" in subject, replies to /home/alerts/abc,
    #   archives the inbox message
"""
import re

# Just `import elastik`. After `pip install elastik` (or
# `pip install -e .` from elastik-pip/ source), the package is on
# sys.path the same way numpy is. No PYTHONPATH gymnastics.
from elastik import listen, MoveTo, Reply, Archive, serve  # noqa: F401


URGENT = re.compile(rb"\b(urgent|outage|down|fire|emergency)\b", re.IGNORECASE)


@listen("/home/inbox/*")
def triage(body: bytes, world: str, meta: dict):
    """If the message looks urgent, broadcast to /home/alerts/.
    Otherwise file under /home/archive/. Source inbox always cleared."""
    subject = meta.get("x-meta-subject", "")
    name = world.rstrip("/").rsplit("/", 1)[-1] or "anon"
    is_urgent = URGENT.search(body) or URGENT.search(subject.encode())
    if is_urgent:
        return [
            Reply(f"/home/alerts/{name}", body, severity="high",
                  source=world, subject=subject),
            Archive(prefix="/home/archive/inbox/"),
        ]
    return Archive(prefix="/home/archive/inbox/")


@listen("/home/outbox/*")
def queue_log(body: bytes, world: str, version: int):
    """Every outbox write also gets a flat log entry. No move; just an
    append-style audit."""
    name = world.rstrip("/").rsplit("/", 1)[-1] or "anon"
    return Reply(
        f"/home/log/outbox/{name}.v{version}",
        body,
        kind="outbox-snapshot",
    )


if __name__ == "__main__":
    # listens for fanouts from elastik-core; calls back into elastik-core
    # via the SDK to execute MoveTo / Reply / Archive / Drop actions.
    serve(host="127.0.0.1", port=3200,
          elastik_url="http://127.0.0.1:3105",
          token="t2")
