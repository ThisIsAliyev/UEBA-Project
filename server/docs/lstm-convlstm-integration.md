# LSTM/ConvLSTM Anomaly Detection Integration

## Overview

Bu sənəd UEBA sisteminə LSTM/ConvLSTM əsaslı anomaliya aşkarlama modelinin inteqrasiyasını təsvir edir. Sistem Tian et al. (2020) tədqiqatına əsaslanır və OpenUBA prinsiplərinə uyğun şəffaf, izahlı anomaliya aşkarlaması təmin edir.

## Architecture

### Model Components

1. **LSTM Sequence Model**
   - İstifadəçinin gündəlik hərəkət ardıcıllığını öyrənir
   - 4 günün ardıcıllığından 5-ci günü proqnozlaşdırır
   - Proqnoz və real ardıcıllıq arasındakı fərq = sequence deviation

2. **ConvLSTM Feature Model**
   - Gündəlik fəaliyyət xüsusiyyətlərini (logon, email, file access) öyrənir
   - Konvolyusiya və LSTM-in birləşməsi ilə xüsusiyyətlərarası əlaqələri öyrənir
   - Proqnoz və real xüsusiyyətlər arasındakı fərq = feature deviation

3. **MLP Classifier**
   - Sequence, feature və role deviasiyalarını birləşdirir
   - Final anomaliya qərarını verir (0-1 ehtimal)

### Data Flow

```
Raw Events → Feature Extraction → Daily Aggregation → Model Inference → Anomaly Score
                                                                              ↓
                                                                    Risk Engine Integration
```

## Installation

### 1. Install Dependencies

```bash
cd server
pip install -r requirements.txt
```

Əsas asılılıqlar:
- TensorFlow >= 2.13.0
- scikit-learn >= 1.3.0
- pandas >= 2.0.0
- numpy >= 1.24.0

### 2. Download CERT Dataset

CERT Insider Threat v4.2 datasını yükləyin:

**Option 1: Kaggle**
```bash
# Kaggle CLI ilə
kaggle datasets download -d nitishabharathi/cert-insider-threat
unzip cert-insider-threat.zip -d data/cert/
```

**Option 2: CMU Kilthub**
- URL: https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247
- Yükləyin və `data/cert/` qovluğuna çıxarın

Dataset strukturu:
```
data/cert/
├── logon.csv
├── email.csv
├── device.csv
├── http.csv
├── file.csv
└── insiders.csv (ground truth)
```

## Training Models

### Basic Training

```bash
python scripts/train_lstm_models.py --max-users 10 --epochs 40
```

### Advanced Training Options

```bash
python scripts/train_lstm_models.py \
    --data-dir data/cert \
    --model-dir data/models/lstm_convlstm \
    --max-users 50 \
    --epochs 100 \
    --reports-dir reports
```

**Parameters:**
- `--max-users`: Təlim üçün maksimum istifadəçi sayı (default: 10)
- `--epochs`: Təlim epoch sayı (default: 40)
- `--data-dir`: CERT dataset qovluğu
- `--model-dir`: Model saxlama qovluğu

**Training Process:**
1. Hər istifadəçi üçün LSTM və ConvLSTM modelləri ayrıca təlim edilir
2. Bütün istifadəçilərin deviasiyaları hesablanır
3. MLP classifier birləşdirilmiş deviasiyalar üzərində təlim edilir
4. Nəticələr `reports/model_training_report.json`-da saxlanır

**Expected Output:**
```
Training Complete!
============================================================
Users attempted: 10
Users successful: 8
Report saved to: reports/model_training_report.json
============================================================
```

## API Usage

### Start Server

```bash
cd server/src
python -m server.app
```

### Training via API

**Start Training:**
```bash
curl -X POST "http://localhost:8000/api/ml/train" \
  -H "Content-Type: application/json" \
  -d '{
    "max_users": 10,
    "epochs": 40,
    "force_retrain": false
  }'
```

**Check Training Status:**
```bash
curl "http://localhost:8000/api/ml/train/status"
```

### Anomaly Detection

**Analyze Specific User-Date:**
```bash
curl -X POST "http://localhost:8000/api/ml/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "ACM2278",
    "date": "2010-05-15"
  }'
```

**Response:**
```json
{
  "user": "ACM2278",
  "date": "2010-05-15",
  "status": "success",
  "anomaly_score": 0.87,
  "anomaly_flag": true,
  "severity": "high",
  "sequence_deviation": 2.34,
  "feature_deviation": 1.89,
  "role_deviation": 0.45
}
```

**Get Explanation:**
```bash
curl "http://localhost:8000/api/ml/explain/ACM2278/2010-05-15"
```

**Response:**
```json
{
  "user": "ACM2278",
  "date": "2010-05-15",
  "anomaly_detected": true,
  "anomaly_score": 0.87,
  "severity": "high",
  "deviations": {
    "sequence": {
      "value": 2.34,
      "description": "Deviation in daily action sequence from normal pattern"
    },
    "features": {
      "value": 1.89,
      "description": "Deviation in activity features (logons, emails, file access, etc.)"
    },
    "role": {
      "value": 0.45,
      "description": "Deviation from typical behavior for user role"
    }
  },
  "interpretation": "Significant anomaly detected: highly unusual action sequence, abnormal activity levels."
}
```

**Get All Anomalies:**
```bash
curl "http://localhost:8000/api/ml/anomalies?min_score=0.7&limit=50"
```

**Get Statistics:**
```bash
curl "http://localhost:8000/api/ml/stats"
```

## Integration with Risk Engine

### Automatic Integration

Risk engine avtomatik olaraq LSTM/ConvLSTM detektorunu yükləyir (əgər aktivdirsə):

```python
from server.risk.risk_engine import RiskEngine

# Risk engine LSTM detector-u avtomatik inteqrasiya edir
risk_engine = RiskEngine()
result = risk_engine.assess_risk(event)

# Result anomaly_score-u ehtiva edir
print(f"Anomaly Score: {result.anomaly_score}")
```

### Manual Integration

```python
from server.risk.lstm_anomaly_detector import LSTMConvLSTMAnomalyDetector

# Detector yaradın
detector = LSTMConvLSTMAnomalyDetector(
    model_dir="data/models/lstm_convlstm",
    enabled=True,
    threshold=0.5
)

# Event üçün anomaliya yoxlayın
score = detector.detect(event, context)

# İzahat alın
explanation = detector.get_explanation(user_id, date)
```

## Features Extracted

### Action Features (23 total)

**Logon/Logoff:**
- Weekday logon/logoff count
- After-hours logon count
- Weekend logon flag
- Online time (hours)

**Device Usage:**
- Number of USB devices connected
- Files copied to USB (by type: exe, jpg, txt/doc/pdf, zip)

**Email Activity:**
- Number of emails sent
- Internal vs external emails
- Email size
- Number of attachments
- After-hours email count

**Web Activity:**
- Number of websites visited
- Career sites visited
- News sites visited
- Tech sites visited

**File Activity:**
- Number of files accessed
- File types accessed

### Action Sequence

Gündəlik hərəkətlərin zaman sıralı ardıcıllığı:
```
Event Types: [logon, logoff, email, http, file_open, file_write, 
              device_connect, device_disconnect, www_job, www_news, 
              www_tech, www_social, www_other]
```

Nümunə ardıcıllıq:
```
[logon, http, email, file_open, http, device_connect, file_write, device_disconnect, email, logoff]
```

## Model Performance

CERT v4.2 dataset üzərində gözlənilən performans (Tian et al. 2020 əsasında):

- **AUC:** ~0.96-0.99
- **Precision:** ~0.97
- **Recall:** ~0.98
- **F1 Score:** ~0.97

## Testing

### Run Unit Tests

```bash
cd server
python tests/test_lstm_models.py
```

**Test Coverage:**
- Model architecture validation
- Feature extraction pipeline
- Training pipeline (smoke tests)
- Inference pipeline
- API endpoints

### Manual Testing

1. **Test Feature Extraction:**
```python
from server.ml.feature_extractor import FeatureExtractor
import pandas as pd

extractor = FeatureExtractor()

# Create sample events
events = pd.DataFrame({
    'timestamp': ['2021-09-01 09:00:00', '2021-09-01 10:30:00'],
    'date': ['2021-09-01', '2021-09-01'],
    'event_type': ['logon', 'email']
})

# Extract features
features = extractor.extract_daily_features(events, '2021-09-01')
print(features)
```

2. **Test Model Loading:**
```python
from server.ml.inference import AnomalyInference

inference = AnomalyInference()
loaded = await inference.load_models_for_user('ACM2278')
print(f"Models loaded: {loaded}")
```

## Troubleshooting

### Issue: CERT Dataset Not Found

**Solution:**
```bash
# Download dataset
mkdir -p data/cert
cd data/cert
# Download from Kaggle or CMU Kilthub
```

### Issue: TensorFlow GPU Not Working

**Solution:**
```bash
# Install CUDA-enabled TensorFlow
pip install tensorflow[and-cuda]

# Verify GPU
python -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"
```

### Issue: Out of Memory During Training

**Solution:**
- Azaldın `--max-users` parametrini
- Azaldın `--epochs` parametrini
- Batch size-ı kiçildin (kod daxilində)

### Issue: Models Not Loading in Inference

**Solution:**
```bash
# Check model files exist
ls -la data/models/lstm_convlstm/

# Should see:
# user_ACM2278_lstm.h5
# user_ACM2278_convlstm.h5
# combined_mlp.h5
```

## Performance Optimization

### Model Caching

Inference engine avtomatik olaraq modelləri cache-də saxlayır:
- Default cache size: 100 models
- LRU eviction policy

### Batch Analysis

Çoxlu günləri analiz etmək üçün batch API istifadə edin:

```python
results = await inference.batch_analyze(
    user_id='ACM2278',
    start_date='2010-05-01',
    end_date='2010-05-31',
    user_events=events_df
)
```

### Background Tasks

FastAPI background tasks ilə uzun müddətli əməliyyatlar:
- Model training
- Daily analysis
- Cache cleanup

## References

1. **Tian, Z. et al. (2020).** "User and Entity Behavior Analysis under Urban Big Data." 
   ACM/IMS Transactions on Data Science, 1(3), Article 16.

2. **CERT Insider Threat Dataset v4.2**
   Carnegie Mellon University, Software Engineering Institute.
   https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247

3. **OpenUBA Project**
   Georgia Cyber Warfare Range.
   https://github.com/GACWR/OpenUBA

4. **variationalkk Implementation**
   https://github.com/variationalkk/User-and-Entity-Behavior-Analytics-UEBA

## License

Bu implementasiya açıq mənbə prinsiplərinə uyğun olaraq hazırlanmışdır və tədqiqat məqsədləri üçün nəzərdə tutulmuşdur.
