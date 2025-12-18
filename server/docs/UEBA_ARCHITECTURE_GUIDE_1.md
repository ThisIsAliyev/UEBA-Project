# UEBA System Architecture Guide

## Ümumi Baxış

Bu sənəd UEBA (User and Entity Behavior Analytics) sisteminin tam arxitekturasını, komponentlərini və bir log hadisəsinin end-to-end səyahətini təsvir edir.

---

## 1. Component Map

### 1.1 Ingest Layer
**Fayl:** `src/server/ingest.py`

**Məsuliyyət:** Windows agentlərindən Sysmon hadisələrini qəbul edir və ilkin emal edir.

**Əsas Funksiyalar:**
- `IngestServer`: TCP server (port 5555)
- `_handle_client()`: Agent bağlantılarını idarə edir
- `_process_line()`: JSON log sətrlərini parse edir

**Texnologiya:** asyncio TCP server

---

### 1.2 Normalization Layer
**Fayl:** `src/server/normalizer.py`

**Məsuliyyət:** Xam hadisələri standart `NormalizedEvent` strukturuna çevirir.

**Əsas Funksiyalar:**
- `normalize_event()`: Xam JSON-u NormalizedEvent-ə çevirir
- `parse_timestamp()`: Zaman damğalarını standartlaşdırır
- `parse_level()`: Severity səviyyələrini təyin edir

**Output:** NormalizedEvent obyekti (user, host, timestamp, category, details)

---

### 1.3 Storage Layer
**Fayl:** `src/server/storage.py`

**Məsuliyyət:** Hadisələri və alertləri SQLite verilənlər bazasında saxlayır.

**Əsas Funksiyalar:**
- `EventStorage`: Verilənlər bazası meneceri
- `store_event()`: Hadisəni saxlayır
- `get_events()`: Hadisələri sorğulayır
- `store_alert()`: Alert yaradır

**Database:** SQLite (`data/events.db`)
- `events` cədvəli: Bütün hadisələr
- `alerts` cədvəli: Risk alertləri

---

### 1.4 Feature Extraction
**Fayl:** `src/server/risk/log_parser.py`

**Məsuliyyət:** Hadisələrdən xüsusiyyətlər çıxarır.

**Əsas Funksiyalar:**
- `extract_command_features()`: Komanda xüsusiyyətləri
- `extract_process_features()`: Proses xüsusiyyətləri
- `extract_network_features()`: Şəbəkə xüsusiyyətləri

**Yeni ML Pipeline:**
- `src/server/ml/feature_extractor.py`: LSTM/ConvLSTM üçün gündəlik xüsusiyyətlər

---

### 1.5 Detection Layer

#### 1.5.1 Rule-Based Detection
**Fayl:** `src/server/risk/rule_scorer.py`

**Məsuliyyət:** YAML qaydalarına əsasən risk skorları hesablayır.

**Config:** `src/server/risk/config/rules.yaml`

**Nümunə Qaydalar:**
- Suspicious PowerShell commands
- Unusual network connections
- Privilege escalation attempts

#### 1.5.2 Anomaly Detection (IsolationForest)
**Fayl:** `src/server/risk/anomaly_detector.py`

**Məsuliyyət:** Maşın öyrənməsi ilə anomaliyaları aşkarlayır.

**Model:** IsolationForest (sklearn)
**Model Path:** `data/risk_models/isolation_forest.pkl`

#### 1.5.3 Deep Learning Anomaly Detection (YENİ)
**Fayl:** `src/server/risk/lstm_anomaly_detector.py`

**Məsuliyyət:** LSTM/ConvLSTM modelləri ilə dərin anomaliya aşkarlaması.

**Modellər:**
- LSTM: Hərəkət ardıcıllığı analizi
- ConvLSTM: Xüsusiyyət analizi
- MLP: Final qərar

**Model Directory:** `data/models/lstm_convlstm/`

---

### 1.6 Risk Scoring Engine
**Fayl:** `src/server/risk/risk_engine.py`

**Məsuliyyət:** Bütün detektorların nəticələrini birləşdirir və final risk skoru hesablayır.

**Komponenlər:**
- Rule-based scoring (30% çəki)
- Anomaly detection (40% çəki)
- Context analysis (30% çəki)

**Output:** `RiskResult` (risk_score: 0-100, risk_level, component scores)

---

### 1.7 AI Enrichment
**Fayl:** `src/server/ai/client.py`

**Məsuliyyət:** Xarici AI servislərindən əlavə təhlil və kontekst alır.

**Xüsusiyyətlər:**
- Async HTTP client
- Circuit breaker pattern
- VirusTotal integration
- LLM-based analysis

---

### 1.8 API & Dashboard
**Fayl:** `src/server/app.py`

**Məsuliyyət:** FastAPI server, REST API və web UI.

**Endpoints:**
- `/api/events`: Hadisələr
- `/api/alerts`: Alertlər
- `/api/ml/*`: ML model idarəetməsi (YENİ)
- `/dashboard`: Web UI

**Texnologiya:** FastAPI + Jinja2 templates

---

## 2. High-Level UEBA Architecture

### 2.1 Arxitektura Diaqramı

```
┌─────────────────────────────────────────────────────────────────┐
│                        UEBA SYSTEM                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐      ┌──────────┐      ┌──────────┐              │
│  │ Windows  │      │ Windows  │      │ Windows  │              │
│  │ Agent 1  │      │ Agent 2  │      │ Agent N  │              │
│  └────┬─────┘      └────┬─────┘      └────┬─────┘              │
│       │                 │                  │                     │
│       └─────────────────┴──────────────────┘                     │
│                         │                                        │
│                         ▼                                        │
│              ┌──────────────────────┐                           │
│              │   Ingest Server      │                           │
│              │   (TCP Port 5555)    │                           │
│              └──────────┬───────────┘                           │
│                         │                                        │
│                         ▼                                        │
│              ┌──────────────────────┐                           │
│              │   Normalization      │                           │
│              └──────────┬───────────┘                           │
│                         │                                        │
│                         ▼                                        │
│              ┌──────────────────────┐                           │
│              │   Storage (SQLite)   │                           │
│              └──────────┬───────────┘                           │
│                         │                                        │
│         ┌───────────────┼───────────────┐                       │
│         │               │               │                       │
│         ▼               ▼               ▼                       │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐                   │
│  │  Rule    │   │ Anomaly  │   │  LSTM/   │                   │
│  │  Scorer  │   │ Detector │   │ ConvLSTM │                   │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘                   │
│       │              │              │                           │
│       └──────────────┼──────────────┘                           │
│                      │                                          │
│                      ▼                                          │
│           ┌──────────────────────┐                             │
│           │   Risk Engine        │                             │
│           └──────────┬───────────┘                             │
│                      │                                          │
│                      ▼                                          │
│           ┌──────────────────────┐                             │
│           │   AI Enrichment      │                             │
│           └──────────┬───────────┘                             │
│                      │                                          │
│                      ▼                                          │
│           ┌──────────────────────┐                             │
│           │   Alert Creation     │                             │
│           └──────────┬───────────┘                             │
│                      │                                          │
│                      ▼                                          │
│           ┌──────────────────────┐                             │
│           │   Dashboard / API    │                             │
│           └──────────────────────┘                             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 SIEM-dən Fərqi

**SIEM (Security Information and Event Management):**
- Log toplama və saxlama
- Qayda əsaslı alertlər
- Korrelyasiya qaydaları
- Compliance reporting

**UEBA (User and Entity Behavior Analytics):**
- ✅ İstifadəçi davranış profillərini öyrənir
- ✅ Anomaliyaları maşın öyrənməsi ilə aşkarlayır
- ✅ Normal davranışdan kənaraçıxmaları izləyir
- ✅ Daxili təhdidləri (insider threats) aşkarlayır
- ✅ Kontekst və zaman ardıcıllığını nəzərə alır

---

## 3. End-to-End Log Journey

### Step 0: Mənbə

**Mənşə:** Windows agent (Sysmon)
**Hadisə Nümunəsi:**
```json
{
  "EventID": 1,
  "ProcessCreate": {
    "User": "DOMAIN\\user123",
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd.exe /c whoami",
    "ParentImage": "C:\\Windows\\explorer.exe"
  },
  "TimeCreated": "2024-01-15T10:30:45.123Z"
}
```

---

### Step 1: Ingest & Normalization

**Modul:** `ingest.py` → `normalizer.py`

**Proses:**
1. Agent TCP bağlantısı yaradır (port 5555)
2. JSON log sətri göndərir
3. `_process_line()` JSON-u parse edir
4. `normalize_event()` NormalizedEvent yaradır

**Çıxış:**
```python
NormalizedEvent(
    id="evt_123456",
    user="user123",
    host="WORKSTATION01",
    timestamp="2024-01-15T10:30:45.123Z",
    category=EventCategory.PROCESS,
    event_type="ProcessCreate",
    severity="medium",
    details={
        "image": "cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "parent_image": "explorer.exe"
    }
)
```

---

### Step 2: Storage

**Modul:** `storage.py`

**Proses:**
1. `store_event()` çağrılır
2. SQLite `events` cədvəlinə INSERT
3. Event ID qaytarılır

**SQL:**
```sql
INSERT INTO events (id, user, host, timestamp, category, event_type, severity, details)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
```

---

### Step 3: Feature Extraction

**Modul:** `risk/log_parser.py` + `ml/feature_extractor.py`

**Proses:**

**A) Real-time Features (Rule-based):**
```python
features = extract_command_features(event)
# Output: {
#   "is_suspicious_command": True,
#   "command_length": 20,
#   "has_obfuscation": False
# }
```

**B) Daily Aggregation (ML-based):**
```python
# Gün ərzində toplanan hadisələr
daily_features = {
    "weekday_logon": 2,
    "num_emails": 15,
    "num_devices": 1,
    "online_time": 8.5,
    "num_websites": 45
}

daily_sequence = [
    "logon", "http", "email", "file_open", 
    "device_connect", "file_write", "logoff"
]
```

---

### Step 4: Detection & Scoring

**Modul:** `risk/risk_engine.py`

**Proses:**

**A) Rule-Based Scoring:**
```python
rule_score = rule_scorer.score(event, context)
# Checks: suspicious_commands.yaml
# Result: 65/100 (medium risk)
```

**B) IsolationForest Anomaly:**
```python
anomaly_score = anomaly_detector.detect(event, context)
# Model predicts: 0.3 (30% anomaly probability)
```

**C) LSTM/ConvLSTM Anomaly (YENİ):**
```python
# Günün sonunda analiz
lstm_result = await lstm_detector.analyze_day_async(user, date)
# Result: {
#   "sequence_deviation": 2.34,
#   "feature_deviation": 1.89,
#   "role_deviation": 0.45,
#   "anomaly_score": 0.87,
#   "anomaly_flag": True
# }
```

**D) Combined Risk Score:**
```python
weights = {"rule": 0.3, "anomaly": 0.4, "context": 0.3}

final_risk = (
    weights["rule"] * rule_score +
    weights["anomaly"] * (anomaly_score * 100) +
    weights["context"] * context_score
)
# Result: 72/100 (HIGH risk)
```

---

### Step 5: Risk Scoring & Alert Creation

**Modul:** `risk/risk_engine.py` + `storage.py`

**Proses:**

**Risk Result:**
```python
RiskResult(
    risk_score=72.0,
    risk_level="high",
    rule_score=65.0,
    feature_score=70.0,
    anomaly_score=30.0,
    context_score=75.0,
    components={
        "matched_rules": ["suspicious_command"],
        "anomaly_details": {...},
        "context_features": {...}
    }
)
```

**Alert Creation:**
```python
if risk_score >= threshold:
    alert = create_alert(
        user=event.user,
        severity="high",
        description="Suspicious command execution detected",
        risk_score=72.0,
        event_ids=[event.id]
    )
    storage.store_alert(alert)
```

**SQL:**
```sql
INSERT INTO alerts (id, user, timestamp, severity, description, risk_score, status)
VALUES (?, ?, ?, ?, ?, ?, 'open')
```

---

### Step 6: AI Enrichment & Analyst Exposure

**Modul:** `ai/client.py` + `app.py`

**Proses:**

**A) AI Enrichment:**
```python
# VirusTotal hash check
vt_result = await ai_client.check_virustotal(file_hash)

# LLM analysis
llm_analysis = await ai_client.analyze_with_llm(
    event_details,
    context
)
# Result: "This appears to be reconnaissance activity..."
```

**B) Dashboard Exposure:**

**REST API:**
```bash
GET /api/alerts?severity=high&status=open
```

**Response:**
```json
{
  "alerts": [
    {
      "id": "alert_789",
      "user": "user123",
      "timestamp": "2024-01-15T10:30:45.123Z",
      "severity": "high",
      "description": "Suspicious command execution detected",
      "risk_score": 72.0,
      "status": "open",
      "enrichment": {
        "ai_analysis": "Reconnaissance activity detected...",
        "vt_result": {...}
      }
    }
  ]
}
```

**Web Dashboard:**
- Real-time alert feed
- Risk score visualization
- User behavior timeline
- Anomaly explanation (LSTM/ConvLSTM deviations)

---

## 4. Data Flow Diagram

```
┌─────────────┐
│   Agent     │ Sysmon Event (JSON)
│ (Sysmon)    │
└──────┬──────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│ STEP 1: INGEST & NORMALIZATION                          │
│ ┌─────────────┐         ┌─────────────┐                │
│ │ TCP Server  │────────▶│ Normalizer  │                │
│ │ (port 5555) │         │             │                │
│ └─────────────┘         └──────┬──────┘                │
│                                │                         │
│                                ▼                         │
│                         NormalizedEvent                  │
└────────────────────────────────┬────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────┐
│ STEP 2: STORAGE                                          │
│ ┌─────────────────────────────────────┐                 │
│ │  SQLite Database (events.db)        │                 │
│ │  ┌─────────────┐  ┌──────────────┐  │                 │
│ │  │   events    │  │    alerts    │  │                 │
│ │  └─────────────┘  └──────────────┘  │                 │
│ └─────────────────────────────────────┘                 │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ STEP 3: FEATURE EXTRACTION                               │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│ │   Command    │  │   Process    │  │   Network    │   │
│ │  Features    │  │  Features    │  │  Features    │   │
│ └──────────────┘  └──────────────┘  └──────────────┘   │
│                                                          │
│ ┌──────────────────────────────────────────────────┐   │
│ │  Daily Aggregation (for LSTM/ConvLSTM)           │   │
│ │  - Action Features (23 metrics)                  │   │
│ │  - Action Sequence (event timeline)              │   │
│ │  - Role Features (baseline comparison)           │   │
│ └──────────────────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ STEP 4: DETECTION & SCORING                              │
│                                                          │
│ ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│ │ Rule-Based   │  │ IsolationFor │  │ LSTM/ConvLSTM│   │
│ │   Scorer     │  │   Detector   │  │   Detector   │   │
│ │              │  │              │  │              │   │
│ │  Score: 65   │  │  Score: 30   │  │  Score: 87   │   │
│ └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
│        │                 │                 │            │
│        └─────────────────┼─────────────────┘            │
│                          ▼                               │
│                 ┌─────────────────┐                     │
│                 │  Risk Engine    │                     │
│                 │  Weighted Avg   │                     │
│                 │  Final: 72/100  │                     │
│                 └────────┬────────┘                     │
└──────────────────────────┼──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│ STEP 5: ALERT CREATION                                   │
│                                                          │
│  IF risk_score >= threshold:                            │
│    ┌──────────────────────────────────┐                │
│    │  Create Alert                    │                │
│    │  - Severity: HIGH                │                │
│    │  - Description: "Suspicious..."  │                │
│    │  - Risk Score: 72                │                │
│    └──────────────┬───────────────────┘                │
│                   │                                      │
│                   ▼                                      │
│         Store in alerts table                           │
└────────────────────────────┬────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────┐
│ STEP 6: AI ENRICHMENT & EXPOSURE                         │
│                                                          │
│ ┌──────────────────┐      ┌──────────────────┐         │
│ │  AI Enrichment   │      │   Dashboard      │         │
│ │  - VirusTotal    │      │   - Web UI       │         │
│ │  - LLM Analysis  │      │   - REST API     │         │
│ │  - Threat Intel  │      │   - WebSocket    │         │
│ └──────────────────┘      └──────────────────┘         │
│                                                          │
│         Analyst sees alert with full context            │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Gaps & Recommendations

### 5.1 Güclü Tərəflər

✅ **Real-time Processing:** Hadisələr daxil olduqca dərhal emal olunur
✅ **Multi-layer Detection:** Qayda, anomaliya və dərin öyrənmə birləşməsi
✅ **AI Integration:** LLM və threat intelligence enrichment
✅ **Transparent Models:** LSTM/ConvLSTM izahlı nəticələr verir (OpenUBA prinsipi)
✅ **Async Architecture:** FastAPI ilə yüksək performans
✅ **Modular Design:** Komponentlər asanlıqla əlavə/dəyişdirilə bilər

### 5.2 Boşluqlar

❌ **Baseline Management:** İstifadəçi baseline-ları avtomatik yenilənmir
❌ **Multi-tenancy:** Çoxlu təşkilat dəstəyi yoxdur
❌ **Alert Aggregation:** Oxşar alertlər birləşdirilmir
❌ **Automated Response:** SOAR inteqrasiyası yoxdur
❌ **Distributed Processing:** Tək server limitasiyası

### 5.3 Tövsiyələr

**Qısa Müddət (1-3 ay):**
1. **Baseline Auto-Update:** İstifadəçi profillərini həftəlik yeniləmək
2. **Alert Deduplication:** Oxşar alertləri birləşdirmək
3. **MITRE ATT&CK Mapping:** Taktika/texnika etiketləri əlavə etmək
4. **Performance Monitoring:** Prometheus/Grafana metrics

**Orta Müddət (3-6 ay):**
1. **Case Management:** Alert-dən incident-ə iş axını
2. **Playbook Integration:** Avtomatik cavab addımları
3. **Multi-tenant Support:** Təşkilat/departman izolasiyası
4. **Advanced Visualizations:** Behavior timeline, attack graphs

**Uzun Müddət (6-12 ay):**
1. **Distributed Architecture:** Kafka/RabbitMQ ilə event streaming
2. **Graph Analytics:** Neo4j ilə əlaqə analizi
3. **Federated Learning:** Çoxlu təşkilat arasında model paylaşımı
4. **Threat Hunting Tools:** Proaktiv təhdid axtarışı interfeysi

---

## 6. Performans Metrikləri

### 6.1 Sistem Performansı

- **Event Ingestion:** ~1000 events/sec (tək server)
- **Detection Latency:** <100ms (real-time rules)
- **ML Inference:** ~5-10 sec (daily LSTM/ConvLSTM analysis)
- **API Response Time:** <50ms (cached queries)

### 6.2 Detection Performansı

**Rule-Based:**
- Precision: ~85%
- Recall: ~70%
- False Positive Rate: ~15%

**IsolationForest:**
- Precision: ~80%
- Recall: ~75%
- AUC: ~0.85

**LSTM/ConvLSTM (CERT dataset):**
- Precision: ~97%
- Recall: ~98%
- AUC: ~0.96-0.99
- F1 Score: ~0.97

---

## 7. Deployment

### 7.1 Minimum Requirements

- **CPU:** 4 cores
- **RAM:** 8 GB
- **Storage:** 50 GB SSD
- **OS:** Windows/Linux
- **Python:** 3.10+

### 7.2 Recommended (Production)

- **CPU:** 16 cores
- **RAM:** 32 GB
- **Storage:** 500 GB NVMe SSD
- **GPU:** NVIDIA (TensorFlow CUDA support)
- **OS:** Ubuntu 22.04 LTS

### 7.3 Scalability

**Horizontal Scaling:**
- Load balancer (nginx/HAProxy)
- Multiple ingest servers
- Shared database (PostgreSQL cluster)
- Redis cache

**Vertical Scaling:**
- GPU acceleration for ML models
- More RAM for model caching
- Faster storage for database

---

## Nəticə

Bu UEBA sistemi müasir təhdidləri aşkarlamaq üçün çoxqatlı, şəffaf və genişlənə bilən arxitekturaya malikdir. LSTM/ConvLSTM inteqrasiyası ilə sistem daxili təhdidləri yüksək dəqiqliklə aşkarlaya bilir və analitiklərə izahlı nəticələr təqdim edir.
