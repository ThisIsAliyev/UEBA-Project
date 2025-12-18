# UEBA Agent Root Cause Analysis Report

**Date:** 2025-12-17  
**Analyst:** Senior UEBA Agent Engineer  
**Report Based On:** UEBAAgent_Diag_Report_20251216_235412.txt/json

---

## 1. ROOT CAUSE QƏRARI

### Primary Root Cause: **H2 — SEND FAILURE / SPOOL DUPLICATE BUG**

**Səbəb:** Agent eventləri toplayır, server-ə göndərməyə çalışır, amma connection per-batch yaradılır və bağlanır. Spool dequeue logic-də kritik bug var: eventlər oxunur, send fail olsa yenidən enqueue olunur → **duplicate accumulation**.

**Sübut (reportdan):**

| Metrik | Dəyər | Şərh |
|--------|-------|------|
| `Events1Min (Security)` | 206 | Normal rate, flood deyil |
| `Events10Min (total)` | 1869 | ~3 event/sec - normal |
| `HighEventRate` | False | Flood yoxdur |
| `SpoolGrowing` | False (stable) | Agent işləmirdi diaq zamanı |
| `Spool size` | 1.74 MB, 1 file | Backlog var, amma artmır |
| `state.json modified` | 10.5 min ago | Agent 10 dəqiqə əvvəl dayanıb |
| `ConnectionReset` | False (diaq zamanı) | Amma agent logunda 10054 var idi |

**Niyə H1 (Historical Flood) FALSE POSITIVE-dir:**

1. `OldEventsPercent` yüksək çıxıb (Sysmon 91.5%, System 99.5%) — **amma bu normal-dır** çünki:
   - Bu kanallarda son 1 dəqiqədə 0-1 event var
   - "Last 200 events" təbii ki köhnə olacaq (az event olan kanalda)
   - Security-də `OldEventsPercent = 0%` — bu kanal aktiv və real-time

2. Agent `start_from_now: True` konfiqurasiyası ilə işləyir
3. RecordId cursor düzgün saxlanılır (`state.json` mövcuddur)
4. Flood rate yoxdur (207 event/min = normal)

**Real problem:**
- Agent hər batch üçün yeni TCP connection açır → overhead
- Send fail olanda eventlər spool-a yazılır
- Spool drain olanda eventlər oxunur, amma file silinmir (əgər max_events-ə çatıbsa)
- Send yenə fail olsa, eyni eventlər **yenidən** spool-a yazılır
- Bu loop backlog-u şişirir

---

## 2. KOD BAZASI AUDIT

### 2.1 Windows Event Collectors

**File:** `agent/src/sysmon_forwarder.py:841-870`

```python
# _fetch_events() metodu
id_filter_clause = ""
if self.event_ids:
    ids_list = list(self.event_ids) if isinstance(self.event_ids, set) else self.event_ids
    if len(ids_list) > 10:
        filter_clause = f"-FilterHashtable @{{LogName='{self.channel}'}}"
        ids_array = "@(" + ",".join(str(i) for i in ids_list) + ")"
        id_filter_clause = f"| Where-Object {{ {ids_array} -contains $_.Id }}"
    else:
        ids_str = ",".join(str(eid) for eid in ids_list)
        filter_clause = f"-FilterHashtable @{{LogName='{self.channel}'; Id=@({ids_str})}}"
else:
    filter_clause = f"-FilterHashtable @{{LogName='{self.channel}'}}"

# RecordId filter
record_id_filter = ""
if self.last_record_id:
    record_id_filter = f"| Where-Object {{ $_.RecordId -gt {self.last_record_id} }}"
```

**Qiymətləndirmə:** ✅ RecordId filter **mövcuddur** və düzgün işləyir. Cursor logic OK.

### 2.2 Cursor/Baseline Logic

**File:** `agent/src/sysmon_forwarder.py:50-101`

```python
class StateManager:
    def set_bookmark(self, channel: str, record_id: int):
        with self._lock:
            if channel not in self._state:
                self._state[channel] = {}
            self._state[channel]["last_record_id"] = record_id
            self._state[channel]["updated_at"] = datetime.now().isoformat()
            self._save_state()  # Hər dəfə disk-ə yazır
```

**Qiymətləndirmə:** ✅ Bookmark hər batch-dən sonra update olunur. OK.

### 2.3 Sender (TCP)

**File:** `agent/src/sysmon_forwarder.py:1270-1357`

```python
def send_events_over_tcp(...) -> bool:
    try:
        sock = socket.create_connection((server_ip, port), timeout=5)
        # ... TLS wrap if needed ...
        try:
            if agent_token:
                auth_msg = json.dumps({"agent_token": agent_token}) + "\n"
                sock.sendall(auth_msg.encode('utf-8'))
            
            for event in events:
                envelope = wrap_event_in_envelope(event)
                json_line = json.dumps(envelope, ensure_ascii=False, default=str)
                data = (json_line + "\n").encode("utf-8")
                sock.sendall(data)
            
            return True
        finally:
            sock.close()
    except socket.timeout:
        return False
    except ConnectionRefusedError:
        return False
    # ... other exceptions ...
```

**Problemlər:**
1. ❌ **Hər batch üçün yeni connection** — overhead, server load
2. ❌ **Backoff yoxdur** — fail olsa dərhal retry
3. ❌ **Partial send handling yoxdur** — 100 event göndərilib, 101-ci fail olsa, hamısı "failed" sayılır
4. ❌ **WinError 10054 xüsusi handling yoxdur**

### 2.4 Spool Queue

**File:** `agent/src/sysmon_forwarder.py:104-256`

```python
def dequeue(self, max_events: int = 200) -> List[Dict]:
    events = []
    with self._lock:
        spool_files = sorted(self.spool_dir.glob("spool_*.ndjson"), ...)
        for spool_file in spool_files:
            # ... read events ...
            # BUG: File yalnız "len(events) < max_events" olduqda silinir
            if len(events) < max_events:
                spool_file.unlink()
```

**Kritik BUG:**
1. ❌ **Dequeue atomic deyil** — eventlər oxunur, amma send fail olsa file qalır
2. ❌ **Re-enqueue duplicate yaradır** — sender fail olanda `spool_queue.enqueue(batch)` çağırılır, amma batch artıq spool-dan oxunmuş eventləri də ehtiva edir
3. ❌ **Inflight tracking yoxdur** — hansı eventlərin "processing" olduğu bilinmir

### 2.5 Server Ingest

**File:** `server/src/server/ingest.py:125-298`

```python
async def _handle_client(self, reader, writer):
    # Auth handling...
    buffer = ""
    while self._running:
        data = await asyncio.wait_for(reader.read(65536), timeout=300.0)
        buffer += data.decode('utf-8', errors='replace')
        while '\n' in buffer:
            line, buffer = buffer.split('\n', 1)
            await self._process_line(line, addr, agent_id)
```

**Qiymətləndirmə:** 
- ✅ NDJSON framing düzgündür
- ✅ Buffer size limit var (10MB)
- ✅ Line size limit var (1MB)
- ⚠️ Exception handling var, amma connection graceful close yoxdur

---

## 3. PATCH PLAN

### Patch A: Spool Safety + Resilient Sender (MÜTLƏQDİR)

1. **Atomic spool drain** — `.sending` rename pattern
2. **Exponential backoff** — send fail olanda artan delay
3. **Duplicate prevention** — spool-dan oxunan eventlər yenidən enqueue olunmasın
4. **Persistent connection** — connection reuse

### Patch B: Server Framing (OPTIONAL)

- Server artıq NDJSON istifadə edir, framing OK
- Yalnız daha yaxşı error logging əlavə edilə bilər

### Patch C: Cursor Fix (LAZIM DEYİL)

- Cursor logic artıq düzgündür
- `start_from_now` işləyir

---

## 4. NƏTİCƏ

**Primary root cause = H2 (Send Failure / Spool Duplicate Bug)**

**Səbəb:** Spool dequeue atomic deyil + send fail olanda eyni eventlər yenidən enqueue olunur → duplicate accumulation → backlog şişir.

**Sübut:** 
- `HighEventRate: False` — flood yoxdur
- `SpoolGrowing: False` (agent işləmirdi) — amma agent işləyəndə 10054 error + spool artırdı
- `OldEventsPercent` yüksək yalnız az-event kanallarda — false positive
- Security kanalı `OldEventsPercent: 0%` — real-time düzgün işləyir

