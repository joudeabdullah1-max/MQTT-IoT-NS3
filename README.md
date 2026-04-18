# NeuroGuard — MQTT IoT AI Defender Simulation
### NS-3 + CNN-BiLSTM-Attention

---

## What This Is

An NS-3 simulation of an IoT MQTT network under DDoS attack, defended by a trained AI model.
Two versions are included: **1-broker** (single network) and **2-broker** (two independent networks).

**Environment:** Ubuntu, NS-3 installed at `~/ns-allinone-3.46.1/ns-3.46.1/`

---

## Files You Need

Place these in `~/ns-allinone-3.46.1/ns-3.46.1/scratch/`:
- `mqtt_1broker_defended.cc` — 1-broker simulation
- `mqtt_2broker_defended.cc` — 2-broker simulation
- `defender_ns3_bridge.py` — shared AI inference bridge

Place trained model weights in `~/Downloads/` (folders named `detector_cnn_bilstm_attn_ft/`, etc.)

---

## How to Run

### Every time before running:
```bash
source ~/ns-allinone-3.46.1/ns-3.46.1/defender_env/bin/activate
cd ~/ns-allinone-3.46.1/ns-3.46.1/
```

### 1-Broker simulation (1 broker, 6 sensors, 1 attacker, 1 defender):
```bash
./ns3 build scratch/mqtt_1broker_defended
./ns3 run scratch/mqtt_1broker_defended
```
Output goes to: `defended_1broker_output/`

### 2-Broker simulation (2 brokers, 15 sensors, 2 attackers, 2 defenders):
```bash
./ns3 build scratch/mqtt_2broker_defended
./ns3 run scratch/mqtt_2broker_defended
```
Output goes to: `defended_2broker_output/`

---

## View Results in NetAnim

```bash
~/ns-allinone-3.46.1/netanim/build/netanim &
```
Open the `.xml` file from the output folder. Press Play.

- Green broker = no threat
- Orange broker = attack blocked
- Amber broker = throttling active
- Red node = attacker
- Purple node = AI defender

---

## Output Files (same structure for both versions)

| File | What it contains |
|------|-----------------|
| `defender_log.csv` (or `_0` / `_1`) | Every defender decision with detection probability |
| `timeseries.csv` | Per-second snapshot of the whole network |
| `summary.csv` | Final TP / FP / TN / FN stats |
| `flows.csv` | Per-flow network statistics |
| `pcap/` | Wireshark packet captures |

---

## Optional Parameters

```bash
./ns3 run "scratch/mqtt_1broker_defended \
    --simTime=180 \
    --attackStart=15 \
    --defInterval=4 \
    --detector=cnn_bilstm_attn \
    --outDir=my_output"
```

Available detectors: `cnn_only`, `cnn_attn`, `cnn_bilstm_attn` (default)

---

## Quick Bridge Test (no simulation needed)

```bash
python3 ~/ns-allinone-3.46.1/ns-3.46.1/scratch/defender_ns3_bridge.py \
    --query    /tmp/test_query.csv \
    --out      /tmp/test_result.json \
    --weights  ~/Downloads \
    --detector cnn_bilstm_attn

cat /tmp/test_result.json
```
If you see `"torch_ok": true` and no `"error"` key, the AI is working.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `ModuleNotFoundError: torch` | Run `source defender_env/bin/activate` first |
| Bridge always returns action=0 | Check the result JSON for an `"error"` key |
| `netanim: No such file` | Use the full path: `~/ns-allinone-3.46.1/netanim/build/netanim` |
| Low TPR (3–8%) | Expected — NS-3 gives aggregate stats, not per-packet features |
| `TypedStorage is deprecated` | Harmless warning, ignore it |
| 2-broker simulation is slow | Normal — two Python AI calls per cycle instead of one |
