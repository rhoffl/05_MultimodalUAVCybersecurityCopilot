import json, time, uuid
from pathlib import Path
from .models import Event, Evidence, Alert

ATTACK = {
  "T0814": "Denial of Service", "T0831": "Manipulation of Control",
  "T0804": "Block Reporting Message", "T0861": "Point & Tag Identification",
}

class CorrelationEngine:
    def __init__(self):
        self.events: list[Event] = []
        self.alerts: list[Alert] = []
        self.audit: list[dict] = []

    def reset(self):
        self.events.clear(); self.alerts.clear(); self.audit.clear()

    def ingest(self, event: Event):
        self.events.append(event)
        self.audit.append({"at": time.time(), "operation": "ingest", "source": event.source, "type": event.event_type})

    def investigate(self, drone_id: str = "UAV-01") -> Alert:
        ev = [x for x in self.events if x.drone_id == drone_id][-100:]
        types = {x.event_type for x in ev}
        score, techniques, findings = 0.05, [], []
        rules = [
          ({"GPS_JUMP", "MISSION_DEVIATION"}, .62, "T0831", "GPS position changed implausibly and the aircraft departed its route"),
          ({"COMMAND_BURST", "UNAUTHORIZED_GCS"}, .62, "T0831", "A command burst originated from an unauthorized ground station"),
          ({"HEARTBEAT_LOSS", "UDP_FLOOD"}, .55, "T0814", "Telemetry heartbeat loss coincided with a network flood"),
          ({"CAMERA_OCCLUSION", "OBJECT_MISMATCH"}, .62, "T0861", "Visual evidence conflicts with expected mission observations"),
          ({"LOG_GAP", "BLOCKED_FLOW"}, .62, "T0804", "Mission reporting stopped while network flow was blocked"),
        ]
        matched_events = []
        for needed, weight, technique, text in rules:
            if needed <= types:
                score += weight; techniques.append(technique); findings.append(text)
                matched_events.extend([x for x in ev if x.event_type in needed])
        score = min(score, .99)
        unique = list({id(x): x for x in matched_events}.values())
        evidence = [Evidence(id=f"EV-{i+1:03}", source=x.source, summary=f"{x.event_type}: {x.attributes}", citation=f"event://{drone_id}/{x.timestamp:.3f}/{x.event_type}", timestamp=x.timestamp) for i,x in enumerate(unique)]
        attack = score >= .6
        sev = "critical" if score >= .9 else "high" if score >= .7 else "medium" if score >= .4 else "low"
        explanation = ("; ".join(findings) if findings else "No cross-source attack pattern met the detection threshold.")
        recs = self._recommend(techniques) if attack else ["Continue monitoring and preserve current telemetry."]
        malicious = [x.timestamp for x in ev if x.ground_truth_attack]
        alert = Alert(id=f"ALT-{uuid.uuid4().hex[:8]}", drone_id=drone_id, title="Correlated UAV cyber incident" if attack else "No confirmed incident", confidence=round(score,2), severity=sev, attack=attack, techniques=sorted(set(techniques)), evidence=evidence, explanation=explanation, recommendations=recs, detected_at=time.time(), first_malicious_at=min(malicious) if malicious else None)
        self.alerts.append(alert)
        self.audit.append({"at": time.time(), "operation":"investigate", "alert_id": alert.id, "attack": attack})
        return alert

    def _recommend(self, techniques):
        out = ["Preserve telemetry, packet captures, mission logs, and relevant frames.", "Require operator approval before any state-changing response."]
        if "T0814" in techniques: out.append("Move telemetry to the pre-authorized backup link and rate-limit the suspected source.")
        if "T0831" in techniques: out.append("Reject untrusted command sources; switch to the approved fail-safe mission profile.")
        if "T0804" in techniques: out.append("Restore reporting through an isolated channel and validate log continuity.")
        return out

    def graph(self, alert: Alert):
        nodes = [{"id": alert.id, "label": alert.title, "kind":"alert"}]
        edges = []
        for e in alert.evidence:
            nodes.append({"id":e.id,"label":e.summary[:44],"kind":e.source}); edges.append({"from":e.id,"to":alert.id,"relation":"supports"})
        for t in alert.techniques:
            nodes.append({"id":t,"label":ATTACK.get(t,t),"kind":"technique"}); edges.append({"from":alert.id,"to":t,"relation":"maps_to"})
        return {"nodes":nodes,"edges":edges}

engine = CorrelationEngine()

def scenario(name: str):
    now = time.time() - 6
    base = [Event(source="mavlink",event_type="HEARTBEAT_OK",timestamp=now,attributes={"mode":"AUTO"})]
    cases = {
      "gps-spoofing": [
        Event(source="mavlink",event_type="GPS_JUMP",timestamp=now+1,severity=4,attributes={"distance_m":821,"interval_s":1},ground_truth_attack=True),
        Event(source="mission",event_type="MISSION_DEVIATION",timestamp=now+2,severity=4,attributes={"cross_track_error_m":314},ground_truth_attack=True),
        Event(source="threat_intel",event_type="STIX_MATCH",timestamp=now+3,attributes={"indicator":"MAVLink navigation manipulation","stix_id":"indicator--demo-gps"},ground_truth_attack=True)],
      "command-injection": [
        Event(source="zeek",event_type="UNAUTHORIZED_GCS",timestamp=now+1,severity=5,attributes={"src":"10.20.0.66"},ground_truth_attack=True),
        Event(source="mavlink",event_type="COMMAND_BURST",timestamp=now+2,severity=5,attributes={"command":"MAV_CMD_COMPONENT_ARM_DISARM","count":23},ground_truth_attack=True)],
      "telemetry-dos": [
        Event(source="suricata",event_type="UDP_FLOOD",timestamp=now+1,severity=5,attributes={"signature":"UAV Telemetry UDP Flood","pps":18005},ground_truth_attack=True),
        Event(source="mavlink",event_type="HEARTBEAT_LOSS",timestamp=now+2,severity=5,attributes={"gap_s":8.4},ground_truth_attack=True)],
      "vision-mismatch": [
        Event(source="vision",event_type="CAMERA_OCCLUSION",timestamp=now+1,severity=3,attributes={"frame":"frame-0042.jpg","occlusion":.91},ground_truth_attack=True),
        Event(source="mission",event_type="OBJECT_MISMATCH",timestamp=now+2,severity=3,attributes={"expected":"tower","observed":"unknown"},ground_truth_attack=True)],
      "benign": [Event(source="mission",event_type="WIND_DEVIATION",timestamp=now+2,attributes={"meters":7.2},ground_truth_attack=False)]
    }
    if name not in cases: raise KeyError(name)
    return base + cases[name]
