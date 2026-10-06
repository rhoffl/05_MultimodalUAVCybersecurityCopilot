import time
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from .models import Event, Approval
from .engine import engine, scenario, ATTACK

app = FastAPI(title="Multimodal UAV Cybersecurity Copilot", version="1.0.0", description="Research prototype using simulated attacks; not safety-certified.")
static = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static), name="static")

@app.get("/")
def home(): return FileResponse(static / "index.html")
@app.get("/health")
def health(): return {"status":"ok", "safety_certified":False}
@app.post("/api/reset")
def reset(): engine.reset(); return {"ok":True}
@app.post("/api/events")
def ingest(event: Event): engine.ingest(event); return {"accepted":True,"count":len(engine.events)}
@app.post("/api/simulate/{name}")
def simulate(name: str):
    try: events=scenario(name)
    except KeyError: raise HTTPException(404,"Unknown scenario")
    for event in events: engine.ingest(event)
    return {"scenario":name,"events":len(events)}
@app.post("/api/investigate")
def investigate(drone_id: str="UAV-01"): return engine.investigate(drone_id)
@app.get("/api/alerts")
def alerts(): return engine.alerts
@app.get("/api/alerts/{alert_id}/graph")
def graph(alert_id: str):
    alert=next((x for x in engine.alerts if x.id==alert_id),None)
    if not alert: raise HTTPException(404,"Alert not found")
    return engine.graph(alert)
@app.post("/api/alerts/{alert_id}/approve")
def approve(alert_id: str, approval: Approval):
    alert=next((x for x in engine.alerts if x.id==alert_id),None)
    if not alert: raise HTTPException(404,"Alert not found")
    alert.status="approved"
    record={"at":time.time(),"operation":"human_approval","alert_id":alert_id,**approval.model_dump()}
    engine.audit.append(record); return record
@app.get("/api/audit")
def audit(): return engine.audit
@app.get("/api/metrics")
def metrics():
    alerts=engine.alerts
    tp=sum(a.attack and a.first_malicious_at is not None for a in alerts); fp=sum(a.attack and a.first_malicious_at is None for a in alerts)
    fn=sum((not a.attack) and a.first_malicious_at is not None for a in alerts); tn=sum((not a.attack) and a.first_malicious_at is None for a in alerts)
    precision=tp/(tp+fp) if tp+fp else 0; recall=tp/(tp+fn) if tp+fn else 0
    mttd=sum(a.detected_at-a.first_malicious_at for a in alerts if a.attack and a.first_malicious_at)/(tp or 1)
    cited=sum(bool(a.evidence) for a in alerts if a.attack); citation_accuracy=cited/(sum(a.attack for a in alerts) or 1)
    return {"precision":round(precision,3),"recall":round(recall,3),"false_positive_rate":round(fp/(fp+tn),3) if fp+tn else 0,"mean_time_to_detect_seconds":round(mttd,2),"evidence_citation_accuracy":round(citation_accuracy,3),"investigation_time_saved_minutes":round(len(alerts)*12.5,1),"agent_task_completion_rate":round(sum(bool(a.explanation and a.recommendations) for a in alerts)/(len(alerts) or 1),3),"sample_size":len(alerts)}

