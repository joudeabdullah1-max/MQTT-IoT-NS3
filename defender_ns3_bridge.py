#!/usr/bin/env python3
"""
defender_ns3_bridge.py
======================
Python bridge between NS-3 and your trained AI defender.

Called by the C++ simulation every g_defEvalInterval seconds:

    python3 defender_ns3_bridge.py  \
        --query   /path/to/defender_query.csv   \
        --out     /path/to/defender_result.json \
        --weights /home/ja/Downloads            \
        --detector cnn_bilstm_attn

Reads 20 rows × 12 feature columns from the query CSV,
runs your saved CNN-BiLSTM-Attn (or chosen variant) detector,
then runs the RL policy to pick a mitigation action.
Writes a single-line JSON result for C++ to parse.

Weight files expected in --weights directory
(matches your Downloads folder screenshot):
  detector_cnn_only_ft
  detector_cnn_attention_ft
  detector_cnn_bilstm_attn_ft
  rl_policy_best_ACCEPTED_cnn_only_ft
  rl_policy_best_ACCEPTED_cnn_attn_ft
  rl_policy_best_ACCEPTED_cnn_bilstm_attn_ft
  scaler_cnn_only_ft.pkl
  scaler_cnn_attention_ft.pkl
  scaler_cnn_bilstm_attn_ft.pkl
"""

import argparse
import json
import math
import pickle
import sys
from pathlib import Path

import numpy as np

# ── Try importing torch ──────────────────────────────────────────────────────
try:
    import torch
    import torch.nn as nn
    TORCH_OK = True
except ImportError:
    TORCH_OK = False

# ── Action names (matches rl_env.py) ────────────────────────────────────────
ACTION_NAMES = {
    0: "ALLOW",           1: "RATE_LIMIT_IP",   2: "TEMP_BLOCK_IP",
    3: "PERM_BLOCK_IP",   4: "DROP_SYN",        5: "DROP_CONNECT",
    6: "DELAY_CONNECT",   7: "LIMIT_PUBLISH",   8: "BLOCK_SUBSCRIBE",
    9: "DISCONNECT",     10: "QUARANTINE",      11: "ISOLATE_NODE",
   12: "REDUCE_QOS",     13: "ALERT_ONLY",      14: "ESCALATE",
   15: "DEESCALATE",
}

# Weight-file name map for each detector variant
WEIGHT_MAP = {
    "cnn_only": {
        "detector": "detector_cnn_only_ft",
        "rl":       "rl_policy_best_ACCEPTED_cnn_only_ft",
        "scaler":   "scaler_cnn_only_ft.pkl",
        "type":     "cnn_only",
    },
    "cnn_attn": {
        "detector": "detector_cnn_attention_ft",
        "rl":       "rl_policy_best_ACCEPTED_cnn_attn_ft",
        "scaler":   "scaler_cnn_attention_ft.pkl",
        "type":     "cnn_attention",
    },
    "cnn_bilstm_attn": {
        "detector": "detector_cnn_bilstm_attn_ft",
        "rl":       "rl_policy_best_ACCEPTED_cnn_bilstm_attn_ft",
        "scaler":   "scaler_cnn_bilstm_attn_ft.pkl",
        "type":     "cnn_bilstm_attn",
    },
}

# ════════════════════════════════════════════════════════════════════════════
#  MODEL DEFINITIONS  (must match defender_simulation_2_.py / rl_env.py)
# ════════════════════════════════════════════════════════════════════════════
if TORCH_OK:
    class MultiHeadAttention(nn.Module):
        def __init__(self, hidden_dim, num_heads=4):
            super().__init__()
            self.num_heads = num_heads
            self.head_dim  = hidden_dim // num_heads
            self.q_proj = nn.Linear(hidden_dim, hidden_dim)
            self.k_proj = nn.Linear(hidden_dim, hidden_dim)
            self.v_proj = nn.Linear(hidden_dim, hidden_dim)
            self.out_proj = nn.Linear(hidden_dim, hidden_dim)
            self.scale = math.sqrt(self.head_dim)

        def forward(self, x):
            B, T, D = x.shape
            Q = self.q_proj(x).view(B, T, self.num_heads, self.head_dim).transpose(1, 2)
            K = self.k_proj(x).view(B, T, self.num_heads, self.head_dim).transpose(1, 2)
            V = self.v_proj(x).view(B, T, self.num_heads, self.head_dim).transpose(1, 2)
            scores = (Q @ K.transpose(-2, -1)) / self.scale
            out = (torch.softmax(scores, dim=-1) @ V)
            out = out.transpose(1, 2).contiguous().view(B, T, D)
            return self.out_proj(out).mean(dim=1)

    class CNN_Only(nn.Module):
        def __init__(self, feat_dim=12, seq_len=20):
            super().__init__()
            self.conv = nn.Sequential(
                nn.Conv1d(feat_dim, 128, 3, padding=1), nn.ReLU(), nn.BatchNorm1d(128),
                nn.Conv1d(128, 128, 3, padding=1),      nn.ReLU(), nn.BatchNorm1d(128),
            )
            self.fc = nn.Sequential(
                nn.Flatten(),
                nn.Linear(128 * seq_len, 128), nn.ReLU(), nn.Dropout(0.3),
                nn.Linear(128, 1),
            )
        def forward(self, x):
            return self.fc(self.conv(x.transpose(1, 2))).squeeze(1)

    class CNN_Attention(nn.Module):
        def __init__(self, feat_dim=12, num_heads=4):
            super().__init__()
            self.conv = nn.Sequential(
                nn.Conv1d(feat_dim, 128, 3, padding=1), nn.ReLU(), nn.BatchNorm1d(128),
                nn.Conv1d(128, 128, 3, padding=1),      nn.ReLU(), nn.BatchNorm1d(128),
            )
            self.attn = MultiHeadAttention(128, num_heads)
            self.fc   = nn.Sequential(
                nn.Linear(128, 128), nn.ReLU(), nn.Dropout(0.3), nn.Linear(128, 1),
            )
        def forward(self, x):
            x = self.conv(x.transpose(1, 2)).transpose(1, 2)
            return self.fc(self.attn(x)).squeeze(1)

    class CNN_BiLSTM_Attn(nn.Module):
        def __init__(self, feat_dim=12, num_heads=4):
            super().__init__()
            self.conv = nn.Sequential(
                nn.Conv1d(feat_dim, 128, 3, padding=1), nn.ReLU(), nn.BatchNorm1d(128),
                nn.Conv1d(128, 128, 3, padding=1),      nn.ReLU(), nn.BatchNorm1d(128),
            )
            self.bilstm = nn.LSTM(128, 64, batch_first=True, bidirectional=True)
            self.attn   = MultiHeadAttention(128, num_heads)
            self.fc     = nn.Sequential(
                nn.Linear(128, 128), nn.ReLU(), nn.Dropout(0.3), nn.Linear(128, 1),
            )
        def forward(self, x):
            x, _ = self.bilstm(self.conv(x.transpose(1, 2)).transpose(1, 2))
            return self.fc(self.attn(x)).squeeze(1)

    class RLPolicy(nn.Module):
        """Matches the DQN / policy network used in rl_train.py"""
        def __init__(self, state_dim=16, action_dim=16, hidden=256):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(state_dim, hidden), nn.ReLU(),
                nn.Linear(hidden, hidden),    nn.ReLU(),
                nn.Linear(hidden, action_dim),
            )
        def forward(self, x):
            return self.net(x)


def _build_detector(det_type: str):
    if det_type == "cnn_only":
        return CNN_Only(feat_dim=12, seq_len=20)
    elif det_type == "cnn_attention":
        return CNN_Attention(feat_dim=12, num_heads=4)
    else:  # cnn_bilstm_attn
        return CNN_BiLSTM_Attn(feat_dim=12, num_heads=4)


# ════════════════════════════════════════════════════════════════════════════
#  FEATURE COLUMNS  (must match rl_env.py add_features())
# ════════════════════════════════════════════════════════════════════════════
FEATURE_COLS = [
    "Time", "time_delta", "Length",
    "has_mqtt_port",
    "flag_syn", "flag_ack", "flag_fin", "flag_rst", "flag_psh", "flag_urg",
    "to_mqtt", "from_mqtt",
]

# ════════════════════════════════════════════════════════════════════════════
#  LOAD WEIGHTS
# ════════════════════════════════════════════════════════════════════════════
_detector_cache = {}
_rl_cache       = {}
_scaler_cache   = {}

def _torch_load(path: Path):
    """
    Load a PyTorch 2.x directory-format checkpoint.
    persistent_id format: ('storage', StorageClass, key_str, location, numel)
    """
    import pickle as _pkl
    path = Path(path)

    if not path.is_dir():
        return torch.load(str(path), map_location="cpu", weights_only=False)

    data_dir = path / "data"

    def persistent_load(saved_id):
        # Format: ('storage', <StorageClass>, '0', 'cpu', numel)
        _tag, storage_cls, key, _location, numel = saved_id
        elem_size = storage_cls().element_size()
        nbytes = int(numel) * elem_size
        fpath = data_dir / str(key)
        with open(str(fpath), "rb") as sf:
            raw = sf.read(nbytes)
        return storage_cls.from_buffer(raw, byte_order="native")

    with open(str(path / "data.pkl"), "rb") as f:
        unpickler = _pkl.Unpickler(f)
        unpickler.persistent_load = persistent_load
        obj = unpickler.load()
    return obj

def load_models(weights_dir: Path, variant: str):
    global _detector_cache, _rl_cache, _scaler_cache
    if variant in _detector_cache:
        return _detector_cache[variant], _rl_cache[variant], _scaler_cache[variant]

    cfg = WEIGHT_MAP[variant]
    det_path = weights_dir / cfg["detector"]
    rl_path  = weights_dir / cfg["rl"]
    sc_path  = weights_dir / cfg["scaler"]

    # ── Detector ────────────────────────────────────────────────────────────
    det_data = _torch_load(det_path)
    det = _build_detector(cfg["type"])
    # det_data may be a state_dict or a full model — handle both
    if isinstance(det_data, dict):
        # plain state_dict
        det.load_state_dict(det_data, strict=False)
    elif hasattr(det_data, "state_dict"):
        # full model object saved directly
        det.load_state_dict(det_data.state_dict(), strict=False)
    else:
        det.load_state_dict(det_data, strict=False)
    det.eval()

    # ── RL policy ────────────────────────────────────────────────────────────
    rl_data = _torch_load(rl_path)
    rl = RLPolicy(state_dim=16, action_dim=16)
    if isinstance(rl_data, dict):
        rl.load_state_dict(rl_data, strict=False)
    elif hasattr(rl_data, "state_dict"):
        rl.load_state_dict(rl_data.state_dict(), strict=False)
    else:
        rl.load_state_dict(rl_data, strict=False)
    rl.eval()

    # ── Scaler ───────────────────────────────────────────────────────────────
    with open(str(sc_path), "rb") as f:
        scaler = pickle.load(f)

    _detector_cache[variant] = det
    _rl_cache[variant]       = rl
    _scaler_cache[variant]   = scaler
    return det, rl, scaler


# ════════════════════════════════════════════════════════════════════════════
#  INFERENCE PIPELINE
# ════════════════════════════════════════════════════════════════════════════
DET_ATTACK_THR  = 0.5
DET_NORMAL_LOW  = 0.3

def run_inference(query_csv: Path, weights_dir: Path, variant: str):
    """
    Returns: (action_id, det_prob, action_name)
    """
    # ── Read query CSV ───────────────────────────────────────────────────────
    import csv
    rows = []
    with open(str(query_csv)) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append([float(row[c]) for c in FEATURE_COLS])

    if len(rows) < 20:
        # Pad with zeros if too few rows
        rows = rows + [[0.0]*12] * (20 - len(rows))
    rows = rows[:20]  # take exactly 20

    X = np.array(rows, dtype=np.float32)  # shape (20, 12)

    if not TORCH_OK:
        # Demo mode — rule-based fallback
        pkt_rate = X[:, 2].mean()          # avg Length
        syn_flag = X[:, 4].mean()          # avg flag_syn
        det_prob = min(1.0, syn_flag * 0.7 + (pkt_rate / 200) * 0.3)
        action   = 2 if det_prob > 0.6 else 1 if det_prob > 0.35 else 0
        return action, float(det_prob), ACTION_NAMES[action]

    det, rl, scaler = load_models(weights_dir, variant)

    # ── Scale features ───────────────────────────────────────────────────────
    # Scaler was fitted on 3 continuous features only: Time, time_delta, Length
    # (columns 0,1,2). The remaining 9 binary flag columns are left unchanged.
    X_scaled = X.copy()
    X_scaled[:, :3] = scaler.transform(X[:, :3])   # scale only cols 0,1,2
    x_tensor = torch.tensor(X_scaled, dtype=torch.float32).unsqueeze(0)  # (1,20,12)

    # ── Detector inference ──────────────────────────────────────────────────
    with torch.no_grad():
        logit    = det(x_tensor)              # (1,)
        det_prob = torch.sigmoid(logit).item()

    # ── Build RL state (16-dim, matches rl_env.py _make_state) ──────────────
    # Features: aggregated stats from sequence + det_prob + prev_action(0) + esc(0)

    # Build state vector matching rl_env.py _make_state() exactly:
    # Index: 0=det_p, 1=time_delta_mean, 2=length_mean, 3=has_mqtt_port_mean,
    #        4=prev_action/15, 5=esc_level/5, 6=fp_ctr/10, 7=fn_ctr/10,
    #        8=flag_syn, 9=flag_ack, 10=flag_fin, 11=flag_rst,
    #        12=flag_psh, 13=flag_urg, 14=to_mqtt, 15=from_mqtt
    time_delta_mean    = float(np.mean(X_scaled[:, 1]))
    length_mean        = float(np.mean(X_scaled[:, 2]))
    has_mqtt_port_mean = float(np.mean(X_scaled[:, 3]))
    flags_mean = np.mean(X_scaled[:, 4:12], axis=0).astype(np.float32)  # 8 values
    extras = np.array([
        det_prob,           # det_p
        time_delta_mean,    # time_delta mean (scaled)
        length_mean,        # length mean (scaled)
        has_mqtt_port_mean, # mqtt port fraction
        0.0,                # prev_action / 15.0
        0.0,                # escalation_level / 5.0
        0.0,                # fp_counter / 10.0
        0.0,                # fn_counter / 10.0
    ], dtype=np.float32)
    state_vec = np.concatenate([extras, flags_mean], axis=0).astype(np.float32)

    state_t = torch.tensor(state_vec, dtype=torch.float32).unsqueeze(0)  # (1,16)

    # ── RL policy ────────────────────────────────────────────────────────────
    with torch.no_grad():
        q_values = rl(state_t)            # (1, 16)
        action   = int(q_values.argmax(dim=1).item())

    return action, float(det_prob), ACTION_NAMES.get(action, "UNKNOWN")


# ════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description="NS-3 ↔ AI Defender bridge")
    parser.add_argument("--query",    required=True,  help="Path to defender_query.csv")
    parser.add_argument("--out",      required=True,  help="Path to write defender_result.json")
    parser.add_argument("--weights",  required=True,  help="Directory with saved model weights")
    parser.add_argument("--detector", default="cnn_bilstm_attn",
                        choices=["cnn_only", "cnn_attn", "cnn_bilstm_attn"],
                        help="Which detector/RL pair to load")
    args = parser.parse_args()

    query_csv   = Path(args.query)
    out_json    = Path(args.out)
    weights_dir = Path(args.weights)
    variant     = args.detector

    if not query_csv.exists():
        result = {"action": 0, "det_prob": 0.0, "action_name": "ALLOW", "error": "query not found"}
        out_json.write_text(json.dumps(result))
        sys.exit(0)

    try:
        action, det_prob, action_name = run_inference(query_csv, weights_dir, variant)
    except Exception as e:
        # On any error fall back to ALLOW so simulation continues
        result = {"action": 0, "det_prob": 0.0, "action_name": "ALLOW", "error": str(e)}
        out_json.write_text(json.dumps(result))
        sys.exit(1)

    result = {
        "action":      action,
        "det_prob":    round(det_prob, 6),
        "action_name": action_name,
        "detector":    variant,
        "torch_ok":    TORCH_OK,
    }
    out_json.write_text(json.dumps(result))
    # Print to stderr so NS-3 logs can capture it (won't pollute C++ stdout)
    print(f"[bridge] action={action} ({action_name})  det_prob={det_prob:.4f}", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
