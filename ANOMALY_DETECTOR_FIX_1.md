# IsolationForest Feature Mismatch Fix

**Tarix:** 2025-12-17  
**Problem:** `X has 9 features, but IsolationForest is expecting 10 features as input`

---

## 1. ROOT CAUSE DİAQNOZU

```
Expected: 10 features (model.n_features_in_)
Got: 9 features (runtime _extract_features())
Missing: 1 feature
Səbəb: Model köhnə feature schema ilə train olunub
```

**Detallı izah:**

| Komponent | Feature Sayı | Feature Mənbəyi |
|-----------|--------------|-----------------|
| `_extract_features()` | **9** | hour_of_day, day_of_week, is_weekend, is_working_hours, user_events_24h, user_unique_source_ips_7d, is_new_source_ip_30d, is_new_host_30d, source_ip_events_24h |
| `SessionAggregator.get_feature_names()` | **15** | process_count, network_connect_count, filecreate_count, registry_count, failed_logon_count, successful_logon_count, unique_dest_ip_count, port_diversity, unique_source_ip_count, unique_process_count, rare_process_count, new_process_count, new_domain_count, suspicious_path_count, total_event_count |
| Model (trained) | **10** | Köhnə versiya - hansı schema ilə train olunduğu bilinmir |

**Problem:** Model 10 feature ilə train olunub, amma `_extract_features()` yalnız 9 feature qaytarır. Bu, ya:
1. Model köhnə versiya ilə train olunub (10 feature var idi)
2. Feature extraction sonradan dəyişib (1 feature silindi)
3. Training zamanı fərqli feature builder istifadə olunub

---

## 2. MVP HOTFIX (Tətbiq olundu)

### Dəyişikliklər (`server/src/server/risk/anomaly_detector.py`):

1. **Rate-limited warning** - Error spam əvəzinə dəqiqədə 1 dəfə warning
2. **Graceful fallback** - Mismatch olanda `anomaly_score = 0.0` qaytarır (crash yox)
3. **Mismatch counter** - Health status-da görünür
4. **Model metadata logging** - Load zamanı `n_features_in_` loglanır

### Davranış:

| Əvvəl | İndi |
|-------|------|
| Hər event üçün error log | Dəqiqədə 1 warning |
| Exception atılır | Default score (0.0) qaytarılır |
| Ingest yavaşlayır | Ingest normal davam edir |
| Client disconnect ola bilər | Stabil connection |

---

## 3. 5 DƏQİQƏLİK VERİFİKASİYA PLANI

### Addım 1: Server-i yenidən başlat (1 dəq)

```bash
# Server-i dayandır
Ctrl+C

# Yenidən başlat
python -m server.app
# və ya
uvicorn server.app:app --reload
```

**Gözlənilən log:**
```
IsolationForest model loaded from ... (expects 10 features)
```

### Addım 2: Agent-dən event göndər (2 dəq)

```powershell
# Agent-i başlat
python run_agent.py

# Test event yarat
notepad.exe
eventcreate /T INFORMATION /ID 999 /L APPLICATION /D "Test"
```

### Addım 3: Server loglarını yoxla (1 dəq)

**Gözlənilən:**
- ❌ `Error scoring event with IsolationForest` spam **OLMAMALIDIR**
- ✅ Dəqiqədə maksimum 1 warning: `Feature mismatch: model expects 10 features, got 9`
- ✅ `Processed X events` normal davam edir

### Addım 4: Health endpoint yoxla (1 dəq)

```bash
curl http://localhost:8080/api/health
```

**Gözlənilən response:**
```json
{
  "anomaly_detector": {
    "status": "healthy",
    "model_available": true,
    "model_n_features": 10,
    "feature_mismatch_count": <N>
  }
}
```

---

## 4. PROPER FIX (Uzunmüddətli - TODO)

MVP hotfix problemi gizlədir, amma həll etmir. Proper fix üçün:

### Seçim A: Modeli yenidən train et (Tövsiyə olunur)

```python
# 9 feature ilə yeni model train et
# _extract_features() ilə uyğun olacaq
python -m server.scripts.train_isolation_forest
```

### Seçim B: Feature schema contract

1. Model train zamanı `isoforest_meta.json` saxla:
```json
{
  "feature_names": ["hour_of_day", "day_of_week", ...],
  "version": "v2",
  "trained_at": "2025-12-17T12:00:00Z"
}
```

2. Runtime-da meta oxu və feature-ları düzəlt:
   - Çatmayan feature → 0 ilə doldur
   - Artıq feature → ignore et

### Seçim C: Feature extraction-ı 10 feature-a qaytar

10-cu feature-in nə olduğunu tap və `_extract_features()`-a əlavə et.

---

## 5. UĞUR KRİTERİYALARI

| Test | Keçdi? |
|------|--------|
| Server start - model metadata loglanır | ☐ |
| 1000 event ingest - error spam yoxdur | ☐ |
| Warning dəqiqədə max 1 dəfə | ☐ |
| Anomaly score 0.0 qaytarılır (crash yox) | ☐ |
| Health endpoint mismatch count göstərir | ☐ |

---

## 6. PATCH SUMMARY

**Dəyişdirilən fayl:** `server/src/server/risk/anomaly_detector.py`

**Əlavə edilən:**
- `import time`
- `_last_mismatch_warning_time` global variable
- `MISMATCH_WARNING_INTERVAL_SEC = 60.0`
- `self._model_n_features` - model feature count tracking
- `self._mismatch_count` - mismatch counter
- Model load zamanı `n_features_in_` logging
- `detect()` və `detect_with_session_features()` metodlarında graceful fallback

