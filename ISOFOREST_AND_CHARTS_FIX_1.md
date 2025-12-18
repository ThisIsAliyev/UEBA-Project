# IsolationForest Spam Fix + GUI Charts Fix

**Tarix:** 2025-12-17  
**Status:** Tamamlandı

---

## QISA İZAH (1 paraqraf)

İki problem həll edildi: 1) **IsolationForest feature mismatch** - model 10 feature gözləyir, amma runtime 9 feature çıxarır. Hotfix olaraq mismatch olanda `anomaly_score=0.0` qaytarılır, exception atılmır, warning dəqiqədə 1 dəfə loglanır. 2) **GUI chart boş görünmə** - timestamp TEXT formatında saxlanırdı və timezone fərqi chart query-lərini boş qaytarırdı. Fix olaraq `ts_ms` (UTC epoch milliseconds) column əlavə edildi və chart query-ləri bu column-dan istifadə edir.

---

## A) IsolationForest Fix

### Dəyişikliklər: `server/src/server/risk/anomaly_detector.py`

1. **Rate-limited warning** (60 saniyədə 1 dəfə)
2. **Graceful fallback** - mismatch olanda `anomaly_score = 0.0`
3. **One-time diagnostic** - ilk mismatch-də model path və feature list loglanır
4. **Health status** - `model_n_features` və `feature_mismatch_count` əlavə edildi

### Davranış:

| Əvvəl | İndi |
|-------|------|
| Hər event üçün ERROR log | Dəqiqədə max 1 WARNING |
| Exception atılır, ingest yavaşlayır | Default score qaytarılır, ingest davam edir |
| Client disconnect ola bilər | Stabil connection |

---

## B) GUI Charts Fix

### Dəyişikliklər: `server/src/server/storage.py`

1. **`ts_ms` column əlavə edildi** - UTC epoch milliseconds
2. **INSERT statements yeniləndi** - `store_event`, `store_events`, `store_events_bulk`
3. **`get_events_summary` yeniləndi** - ts_ms ilə timezone-safe bucketing
4. **Fallback** - köhnə eventlər (ts_ms=NULL) üçün TEXT timestamp fallback

### Davranış:

| Əvvəl | İndi |
|-------|------|
| TEXT timestamp, timezone drift | UTC epoch ms, timezone-safe |
| Chart query boş qayıdır | Chart query düzgün işləyir |
| Bucket hesablaması səhv | Bucket hesablaması dəqiq |

---

## 5 DƏQİQƏLİK VERİFİKASİYA PLANI

### Addım 1: Server-i yenidən başlat (1 dəq)

```bash
cd server/src
python -m server.app
# və ya
uvicorn server.app:app --host 0.0.0.0 --port 8080
```

**Gözlənilən log:**
```
IsolationForest model loaded from ... (expects 10 features)
```

### Addım 2: Agent-dən event göndər (1 dəq)

```powershell
# Agent-i başlat
cd agent
python run_agent.py

# Test event yarat
notepad.exe
calc.exe
```

### Addım 3: Server loglarını yoxla (1 dəq)

**Gözlənilən:**
- ❌ `Error scoring event with IsolationForest` spam **YOX**
- ✅ Bir dəfə: `=== FEATURE MISMATCH DIAGNOSTIC (one-time) ===`
- ✅ Dəqiqədə max 1: `Feature mismatch: model expects 10, got 9. score=0.0`
- ✅ `Processed X events` normal davam edir

### Addım 4: GUI-ni yoxla (1 dəq)

1. Browser-də `http://localhost:8080/events` aç
2. **Events Over Time** chart-ına bax
3. **Events by Source** donut chart-ına bax

**Gözlənilən:**
- ✅ Chart-lar dolu görünür (boş deyil)
- ✅ Son 1 saat / 24 saat seçəndə data görünür
- ✅ Counter-lar və chart-lar uyğundur

### Addım 5: API endpoint yoxla (1 dəq)

```bash
curl "http://localhost:8080/api/events/summary?hours=1"
```

**Gözlənilən response:**
```json
{
  "timeline": {
    "2025-12-17 09:15:00": 5,
    "2025-12-17 09:30:00": 12,
    ...
  },
  "by_source": {
    "sysmon": 100,
    "security": 50
  },
  "bucket_size": 1
}
```

---

## UĞUR KRİTERİYALARI

| Test | Keçdi? |
|------|--------|
| Server start - model metadata loglanır | ☐ |
| IsolationForest ERROR spam yoxdur | ☐ |
| Warning dəqiqədə max 1 dəfə | ☐ |
| Ingest dayanmır, disconnect azalır | ☐ |
| GUI "Events Over Time" chart dolu | ☐ |
| GUI "Events by Source" chart dolu | ☐ |
| API /api/events/summary timeline qaytarır | ☐ |

---

## DƏYİŞDİRİLƏN FAYLLAR

### 1. `server/src/server/risk/anomaly_detector.py`

```diff
+ import time
+ _last_mismatch_warning_time: float = 0.0
+ MISMATCH_WARNING_INTERVAL_SEC: float = 60.0
+ _mismatch_diag_logged: bool = False

+ self._model_n_features: Optional[int] = None
+ self._mismatch_count: int = 0

# _load_model():
+ if hasattr(self._model, 'n_features_in_'):
+     self._model_n_features = self._model.n_features_in_
+     self._logger.info("... (expects %d features)", ...)

# detect():
+ # One-time diagnostic logging
+ if not _mismatch_diag_logged:
+     _mismatch_diag_logged = True
+     self._logger.warning("=== FEATURE MISMATCH DIAGNOSTIC ===...")
+ # Rate-limited warning
+ if current_time - _last_mismatch_warning_time >= 60:
+     self._logger.warning("Feature mismatch: ...")
+ return self._default_score  # No crash

# get_health_status():
+ "model_n_features": self._model_n_features,
+ "feature_mismatch_count": self._mismatch_count,
```

### 2. `server/src/server/storage.py`

```diff
# Schema migration:
+ ("ts_ms", "INTEGER"),  # UTC epoch milliseconds

# Index:
+ CREATE INDEX IF NOT EXISTS idx_events_ts_ms ON events(ts_ms DESC)

# store_event(), store_events(), store_events_bulk():
+ ts_ms = int(event.ingested_at.timestamp() * 1000)
+ ... ts_ms column in INSERT

# get_events_summary():
+ now_ms = int(datetime.utcnow().timestamp() * 1000)
+ cutoff_ms = now_ms - (hours * 3600 * 1000)
+ # Query using ts_ms for timezone-safe bucketing
+ SELECT (ts_ms / bucket_size_ms) * bucket_size_ms as bucket_ms, COUNT(*)
+ FROM events WHERE ts_ms > ?
+ # Fallback for old events without ts_ms
```

---

## PROPER FIX (Uzunmüddətli - TODO)

### IsolationForest üçün:
1. Modeli 9 feature ilə yenidən train et
2. Və ya `_extract_features()`-a 10-cu feature əlavə et
3. Model metadata faylı saxla (`isoforest_meta.json`)

### Charts üçün:
- Köhnə eventlər üçün migration script yaz:
```sql
UPDATE events 
SET ts_ms = CAST(strftime('%s', ingested_at) AS INTEGER) * 1000
WHERE ts_ms IS NULL;
```

