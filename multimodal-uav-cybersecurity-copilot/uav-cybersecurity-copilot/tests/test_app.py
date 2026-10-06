from fastapi.testclient import TestClient
from app.main import app
from app.engine import engine

client=TestClient(app)
def setup_function(): engine.reset()
def test_health(): assert client.get('/health').json()['safety_certified'] is False
def test_gps_attack_is_detected_with_citations():
    assert client.post('/api/simulate/gps-spoofing').status_code==200
    a=client.post('/api/investigate').json()
    assert a['attack'] is True and a['confidence'] >= .6
    assert 'T0831' in a['techniques'] and len(a['evidence']) >= 2
    assert all(x['citation'].startswith('event://') for x in a['evidence'])
def test_benign_does_not_alert():
    client.post('/api/simulate/benign'); assert client.post('/api/investigate').json()['attack'] is False

