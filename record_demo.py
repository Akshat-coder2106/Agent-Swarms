import asyncio
import json
from pathlib import Path
from backend.sentinel.orchestrator import SentinelOrchestrator
from backend.sentinel.models import AuditRequest, AuditEvent
from backend.sentinel.config import load_settings

async def main():
    settings = load_settings()
    orchestrator = SentinelOrchestrator(settings=settings)
    
    # 1. Create session
    req = AuditRequest(repo_path="/Users/akshatagrawal/Desktop/Agent Swarms/examples/python-vulnerable-api", objective="Audit for demo")
    session = await orchestrator.create_session(req)
    queue = await orchestrator.event_bus.subscribe(session.session_id)
    
    events = []
    print(f"Recording session {session.session_id}...")
    
    # Wait for completion
    while True:
        try:
            event = await asyncio.wait_for(queue.get(), timeout=10.0)
            events.append(event.model_dump(mode="json"))
            if event.event_type in ("SESSION_COMPLETED", "SESSION_FAILED"):
                break
        except asyncio.TimeoutError:
            print("Timeout waiting for events. Saving what we have.")
            break
            
    # Also grab the final session state
    final_session = await orchestrator.get_session(session.session_id)
    
    recording = {
        "session": final_session.model_dump(mode="json"),
        "events": events
    }
    
    with open("backend/demo_recording.json", "w") as f:
        json.dump(recording, f, indent=2)
        
    print("Saved demo_recording.json")

if __name__ == "__main__":
    asyncio.run(main())
