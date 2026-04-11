# NS-3 MQTT IoT Simulation — Project README
Repository containing the NS-3 simulation code for the NeuroGuard project, including MQTT-based IoT network scenarios with normal and DDoS attack traffic.

## Environment Setup

Our simulation was proceeded using **Oracle VM VirtualBox** on a Windows host machine, with an **Ubuntu (64-bit)** virtual environment. The NS-3 package (`ns-allinone-3.46.1`) was installed and configured within this environment. The network topology was implemented inside the **scratch directory**, where custom scripts were developed to build and control the simulated network.

---

## Project Overview

This project simulates MQTT-based IoT networks under normal conditions and under Reinforcement Learning (RL)-controlled DDoS attacks, using real MQTT 3.1.1 binary frames transmitted over TCP port 1883. The simulations model physical IoT sensor hardware publishing to MQTT brokers in a wireless ad-hoc (802.11b) environment.

### Simulation Files

| File | Description | Output Directory |
|------|-------------|-----------------|
| `mqtt_1broker_normal.cc` | 1 Broker + 6 Sensors, no attack | `normal_1broker_output/` |
| `mqtt_1broker_attack.cc` | 1 Broker + 6 Sensors + 1 RL Attacker | `attack_1broker_output/` |
| `mqtt_2broker_normal.cc` | 2 Brokers + 20 Sensors + Bridge, no attack | `normal_2broker_output/` |
| `mqtt_2broker_attack.cc` | 2 Brokers + 20 Sensors + 1 RL Attacker (parallel) | `attack_2broker_output/` |

---

## Sensor Types Simulated

| Sensor | Model | MQTT Topic | Payload Example |
|--------|-------|-----------|----------------|
| Temperature & Humidity | DHT22 | `sensors/temperature_humidity` | `T:24.5 H:61.3` |
| Water Level | HC-SR04 | `sensors/water_level` | `Level:Normal` / `Level:High` |
| Ultrasonic Distance | HC-SR04 | `sensors/ultrasonic` | `18.938 cm` |
| Flame / IR Detection | KY-026 | `sensors/flame_ir` | `0` / `Flame Detected!` |
| Motion Detection | PIR HC-SR501 | `sensors/motion` | `Motion Detected!` / `No Motion` |
| Light Intensity | BH1750 | `sensors/light` | `Lux:320.5` |

---

## Network Topologies

### 1-Broker Network (Star Topology)
```
        [S1: Temp/Hum]   [S2: WaterLvl]
              \               /
    [S6:Light]--[  BROKER  ]--[S3: Ultrasonic]
              /               \
        [S5: Motion]   [S4: Flame/IR]

  Subnet: 10.0.0.0/24 | Protocol: 802.11b Ad-Hoc
  Broker: 10.0.0.1    | Sensors: 10.0.0.2 - 10.0.0.7
  Attacker (attack version): 10.0.0.8
```

### 2-Broker Network (Dual Star + Bridge)
```
  LAN0 (10.0.0.0/24)          LAN1 (10.0.1.0/24)
  ┌─────────────────────┐      ┌─────────────────────┐
  │  S00-S09 in arc     │      │  S10-S19 in arc     │
  │   around BROKER0    │======│   around BROKER1    │
  │    10.0.0.1         │Bridge│    10.0.1.1         │
  │                     │:1884 │                     │
  │  [!ATTACKER!]       │      │  (clean traffic)    │
  │   10.0.0.12         │      │                     │
  └─────────────────────┘      └─────────────────────┘
  Bridge subnet: 10.0.2.0/24
```

---

## Attack Modes

The attacker uses Q-learning to adaptively switch between 5 DDoS strategies:

| Mode | Name | Description | Packet Rate |
|------|------|-------------|------------|
| 0 | SYN | Rapid TCP SYN connection flood | δ = 1.709s |
| 1 | BASIC | Standard MQTT CONNECT flood | δ = 0.476s |
| 2 | DELAY | Slow connect, delayed payload | δ = 0.890s |
| 3 | INVSUB | Invalid MQTT SUBSCRIBE topic | δ = 0.751s |
| 4 | WILL | CONNECT with large WILL payload | δ = 0.490s |

**RL Parameters:** ε-greedy exploration (ε₀=0.90, decay=0.98, floor=0.05), γ=0.95, α=0.10

---

## How to Run the Simulations

### Prerequisites

```bash
# Inside your Ubuntu VM — verify NS-3 is installed
cd ~/ns-allinone-3.46.1/ns-3.46
./ns3 --version    # should print "ns-3.46.1"
```

### Step 1: Copy simulation files to scratch directory

```bash
cp mqtt_1broker_normal.cc  ~/ns-allinone-3.46.1/ns-3.46/scratch/
cp mqtt_1broker_attack.cc  ~/ns-allinone-3.46.1/ns-3.46/scratch/
cp mqtt_2broker_normal.cc  ~/ns-allinone-3.46.1/ns-3.46/scratch/
cp mqtt_2broker_attack.cc  ~/ns-allinone-3.46.1/ns-3.46/scratch/
```

### Step 2: Navigate to NS-3 directory

```bash
cd ~/ns-allinone-3.46.1/ns-3.46
```

### Step 3: Build and run each simulation

```bash
# 1-Broker Normal (no attack)
./ns3 run scratch/mqtt_1broker_normal

# 1-Broker with RL-DDoS Attack
./ns3 run scratch/mqtt_1broker_attack

# 2-Broker Normal (parallel, no attack)
./ns3 run scratch/mqtt_2broker_normal

# 2-Broker with RL-DDoS Attack (parallel, 1 attacker)
./ns3 run scratch/mqtt_2broker_attack
```

### Optional: Custom Parameters

```bash
# Change simulation duration, attack timing, and output folder
./ns3 run scratch/mqtt_1broker_attack \
  "--simTime=120 --attackStart=15 --evalInterval=10 --epsilon=0.85 --outDir=my_results"

./ns3 run scratch/mqtt_2broker_attack \
  "--simTime=120 --attackStart=20 --seed=123"
```

---

## Output Files

Each simulation generates an output directory containing:

```
<output_dir>/
├── pcap/
│   ├── broker0-0-0.pcap         ← Open in Wireshark, filter: mqtt
│   ├── broker1-0-0.pcap         ← (2-broker simulations only)
│   └── attacker-0-0.pcap        ← (attack simulations only)
├── flows.csv                    ← Per-flow statistics (loss, delay, throughput)
├── rl_log.csv                   ← RL Q-table evolution (attack simulations only)
├── timeseries.csv               ← Per-second bandwidth breakdown
├── summary.csv                  ← Aggregate stats + final RL Q-table
├── mqtt-*-anim.xml              ← NetAnim animation file
└── mqtt-*-flowmonitor.xml       ← NS-3 FlowMonitor raw XML
```

---

## Viewing the Animation (NetAnim)

```bash
# Launch NetAnim (already included in ns-allinone)
~/ns-allinone-3.46.1/netanim-3.109/NetAnim &

# Then: File → Open → select the .xml animation file
# Use the Play button, zoom in on clusters, click nodes to inspect
```

**Node Color Legend in NetAnim:**
- 🟢 **Green** — MQTT Broker
- 🔵 **Blue** — IoT Sensor (standard)
- 🟠 **Orange** — Flame/IR Hazard Sensor
- 🔴 **Red** — RL DDoS Attacker

---

## Analyzing Results with Wireshark

```bash
# Open broker PCAP and filter for MQTT frames only
wireshark normal_1broker_output/pcap/broker0-0-0.pcap

# Wireshark display filter:
mqtt

# You will see decoded MQTT frames:
#   MQTT CONNECT    (sensor connecting to broker)
#   MQTT CONNACK    (broker accepting connection)
#   MQTT PUBLISH    (sensor sending data)
#   MQTT SUBSCRIBE  (attacker mode 3 — invalid subscription)
```

---

## Expected Results

### Normal Simulations (No Attack)
- **Loss rate:** < 1% (wireless channel only)
- **Sensor traffic:** steady low-bandwidth MQTT PUBLISH flows
- **NetAnim:** clean packet animations between sensors and broker(s)
- **timeseries.csv:** stable kbps values throughout simulation

### Attack Simulations
- **Phase 1 (t=0 to attackStart):** identical to normal — sensors publishing normally
- **Phase 2 (t=attackStart onwards):** attacker begins flooding; broker load increases
- **RL behavior:** every `evalInterval` seconds, the Q-table updates based on packet loss ratio; attack mode may switch to maximize disruption
- **flows.csv:** attack flows show higher tx_packets vs sensor flows
- **rl_log.csv:** tracks Q-value evolution, epsilon decay, mode transitions
- **Expected loss on Broker0 (2-broker attack):** elevated vs Broker1 (clean)

### Sample rl_log.csv structure:
```
time_s,step,prev_mode,prev_name,new_mode,new_name,loss_ratio,reward,...
18.00,1,0,SYN,1,BASIC,0.3200,0.36,0.8820,...
26.00,2,1,BASIC,1,BASIC,0.1900,0.62,0.8644,...
34.00,3,1,BASIC,4,WILL,0.1100,0.78,0.8471,...
```

---

## Generating Plots from CSV Output

Use Python + matplotlib to visualize results:

```python
import pandas as pd
import matplotlib.pyplot as plt

# Plot attack vs sensor bandwidth over time
ts = pd.read_csv("attack_1broker_output/timeseries.csv")
plt.figure(figsize=(12,5))
plt.plot(ts["time_s"], ts["sensor_kbps"], label="Sensor Traffic (kbps)", color="steelblue")
plt.plot(ts["time_s"], ts["attack_kbps"], label="Attack Traffic (kbps)", color="red")
plt.axvline(x=10, color="orange", linestyle="--", label="Attack Start (t=10s)")
plt.xlabel("Time (s)"); plt.ylabel("Bandwidth (kbps)")
plt.title("MQTT IoT Traffic Under RL-DDoS Attack"); plt.legend(); plt.grid(True)
plt.savefig("bandwidth_over_time.png", dpi=150)

# Plot RL Q-table evolution
rl = pd.read_csv("attack_1broker_output/rl_log.csv")
for col in ["q0_SYN","q1_BASIC","q2_DELAY","q3_INVSUB","q4_WILL"]:
    plt.plot(rl["time_s"], rl[col], label=col)
plt.xlabel("Time (s)"); plt.ylabel("Q-value")
plt.title("RL Agent Q-Table Evolution"); plt.legend(); plt.grid(True)
plt.savefig("rl_qtable.png", dpi=150)
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `./ns3: command not found` | Run `python3 ns3` or check you are in the ns-3.46 directory |
| Build errors: unknown TypeId | Each .cc file uses unique TypeId names (e.g. `MqttBrokerApp1N`) — do not mix files in the same build |
| NetAnim shows empty canvas | Check that the .xml file is not 0 bytes; re-run simulation with `NS_LOG=...` |
| PCAP files are very small | Normal — MQTT frames are tiny (61–162 bytes); Wireshark will still decode them |
| Simulation runs but no rl_log.csv | Expected for normal (no-attack) simulations; only attack versions generate this file |

---

## Project Structure

```
project/
├── mqtt_1broker_normal.cc     ← 1 broker, 6 sensors, no attack
├── mqtt_1broker_attack.cc     ← 1 broker, 6 sensors, RL attacker
├── mqtt_2broker_normal.cc     ← 2 brokers, 20 sensors, no attack
├── mqtt_2broker_attack.cc     ← 2 brokers, 20 sensors, 1 RL attacker (parallel)
└── README.md                  ← This file

After running:
├── normal_1broker_output/
├── attack_1broker_output/
├── normal_2broker_output/
└── attack_2broker_output/
```

---

*Simulation environment: Oracle VM VirtualBox | Ubuntu 64-bit | NS-3 ns-allinone-3.46.1*

