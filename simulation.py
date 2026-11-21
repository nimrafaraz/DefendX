"""Deterministic simulators and detectors for RF, network and radar.

PURE FUNCTIONS: no database, no network, no Streamlit. Everything is synthetic.
Every simulator takes a seed, so the same seed always draws the same picture.

SAFETY: no real radio, network or radar data is read or sent. Network "attacks"
are just rows in a table, and all outside addresses come from the reserved
documentation ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24.
"""
from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

# =====================================================================
# 1. ELECTRONIC ACTIVITY (RF)
# =====================================================================
FREQ_MIN_MHZ, FREQ_MAX_MHZ = 400.0, 470.0
FREQS = np.round(np.arange(4000, 4701) / 10.0, 1)        # 400.0 ... 470.0 in 0.1 MHz steps
NOISE_FLOOR_DBM = -105.0
NOISE_SIGMA_DB = 1.5
PEAK_MARGIN_DB = 15.0        # a peak must be this far above the median
MATCH_TOLERANCE_MHZ = 0.6    # a peak this close to a planned emitter "matches" it
DEVIATION_DB = 8.0           # power change vs baseline that counts as a deviation
NOISE_RISE_DB = 6.0          # median this far above the floor = broadband noise rise

AUTHORISED_EMITTERS = (
    {"name": "Base Net Alpha", "freq_mhz": 410.0, "power_dbm": -62.0, "bw_mhz": 0.4},
    {"name": "Logistics Net", "freq_mhz": 425.5, "power_dbm": -70.0, "bw_mhz": 0.3},
    {"name": "Air Ops Link", "freq_mhz": 438.2, "power_dbm": -58.0, "bw_mhz": 0.5},
    {"name": "Telemetry Beta", "freq_mhz": 452.0, "power_dbm": -75.0, "bw_mhz": 0.3},
    {"name": "Patrol Net", "freq_mhz": 463.4, "power_dbm": -66.0, "bw_mhz": 0.4},
)
RF_SCENARIOS = ("Normal", "Unknown emitter", "Power deviation",
                "Offline emitter", "Noise floor rise")
_UNKNOWN_EMITTER = {"freq_mhz": 444.7, "power_dbm": -55.0, "bw_mhz": 0.3}
_DEVIATION_INDEX, _OFFLINE_INDEX = 1, 3


def simulate_sweep(seed: int, scenario: str = "Normal") -> dict:
    """Draw one 400-470 MHz sweep. Returns freqs, power_dbm and the scenario used."""
    if scenario not in RF_SCENARIOS:
        raise ValueError(f"Unknown RF scenario: {scenario}")
    rng = np.random.default_rng(seed)
    floor = NOISE_FLOOR_DBM + (9.0 if scenario == "Noise floor rise" else 0.0)
    noise_dbm = floor + rng.normal(0.0, NOISE_SIGMA_DB, len(FREQS))
    jitter = rng.normal(0.0, 0.7, len(AUTHORISED_EMITTERS))      # drawn for every scenario
    linear = 10 ** (noise_dbm / 10)                              # add signals in milliwatts

    def add(freq, power, bw):
        nonlocal linear
        linear = linear + 10 ** ((power - 12.0 * ((FREQS - freq) / bw) ** 2) / 10)

    for i, e in enumerate(AUTHORISED_EMITTERS):
        if scenario == "Offline emitter" and i == _OFFLINE_INDEX:
            continue
        power = e["power_dbm"] + jitter[i]
        if scenario == "Power deviation" and i == _DEVIATION_INDEX:
            power += 12.0
        add(e["freq_mhz"], power, e["bw_mhz"])
    if scenario == "Unknown emitter":
        add(_UNKNOWN_EMITTER["freq_mhz"], _UNKNOWN_EMITTER["power_dbm"], _UNKNOWN_EMITTER["bw_mhz"])
    return {"freqs": FREQS.copy(), "power_dbm": 10 * np.log10(linear),
            "scenario": scenario, "seed": seed}


def simulate_waterfall(seed: int, scenario: str = "Normal", n_sweeps: int = 30,
                       anomaly_sweeps: int = 8) -> np.ndarray:
    """n_sweeps rows (oldest first). The scenario appears in the newest sweeps."""
    rows = []
    for i in range(n_sweeps):
        sc = scenario if i >= n_sweeps - anomaly_sweeps else "Normal"
        rows.append(simulate_sweep(seed * 1000 + i, sc)["power_dbm"])
    return np.vstack(rows)


def find_peaks(freqs, power, margin_db: float = PEAK_MARGIN_DB) -> list[tuple[float, float]]:
    """Return (freq, power) of each spectral peak above median + margin."""
    threshold = float(np.median(power)) + margin_db
    above = power > threshold
    peaks, i, n = [], 0, len(power)
    while i < n:
        if above[i]:
            j = i
            while j + 1 < n and above[j + 1]:
                j += 1
            k = i + int(np.argmax(power[i:j + 1]))
            peaks.append((float(freqs[k]), float(power[k])))
            i = j + 1
        else:
            i += 1
    return peaks


def detect_rf(freqs, power, plan=AUTHORISED_EMITTERS) -> list[dict]:
    """Compare a sweep with the authorised plan and return anomaly detections."""
    detections: list[dict] = []
    src = "RF sweep 400-470 MHz"
    rise = float(np.median(power)) - NOISE_FLOOR_DBM
    if rise > NOISE_RISE_DB:
        detections.append({
            "kind": "NOISE_FLOOR_RISE", "severity": "MEDIUM", "freq_mhz": None,
            "power_dbm": float(np.median(power)), "source": src,
            "title": "Broadband noise-floor rise",
            "details": f"Median level is {rise:.1f} dB above the {NOISE_FLOOR_DBM:.0f} dBm floor."})

    unmatched = list(range(len(plan)))
    for freq, pwr in find_peaks(freqs, power):
        best = min(unmatched, key=lambda i: abs(plan[i]["freq_mhz"] - freq), default=None)
        if best is not None and abs(plan[best]["freq_mhz"] - freq) <= MATCH_TOLERANCE_MHZ:
            unmatched.remove(best)
            e = plan[best]
            delta = pwr - e["power_dbm"]
            if abs(delta) > DEVIATION_DB:
                detections.append({
                    "kind": "POWER_DEVIATION", "severity": "MEDIUM", "freq_mhz": freq,
                    "power_dbm": pwr, "source": src,
                    "title": f"Power deviation on {e['name']}",
                    "details": f"{e['name']} at {freq:.1f} MHz is {delta:+.1f} dB from its "
                              f"baseline of {e['power_dbm']:.0f} dBm."})
        else:
            sev = "HIGH" if pwr >= -60 else "MEDIUM" if pwr >= -75 else "LOW"
            detections.append({
                "kind": "UNKNOWN_EMITTER", "severity": sev, "freq_mhz": freq,
                "power_dbm": pwr, "source": src,
                "title": f"Unknown emitter at {freq:.1f} MHz",
                "details": f"Peak of {pwr:.1f} dBm matches no authorised emitter."})

    for i in unmatched:
        e = plan[i]
        detections.append({
            "kind": "EMITTER_OFFLINE", "severity": "MEDIUM", "freq_mhz": e["freq_mhz"],
            "power_dbm": None, "source": src, "title": f"Emitter offline: {e['name']}",
            "details": f"No signal found near planned {e['freq_mhz']:.1f} MHz."})
    return detections


# =====================================================================
# 2. CYBER DEFENCE (synthetic flow records)
# =====================================================================
CYBER_SCENARIOS = ("Normal traffic", "Port scan", "Brute force",
                   "Data exfiltration", "Traffic flood")
PORT_SCAN_MIN_PORTS = 15
BRUTE_FORCE_MIN_FAILS = 20
EXFIL_MIN_BYTES = 50_000_000
FLOOD_MIN_SOURCES = 30
FLOOD_MIN_PACKETS = 20_000
WINDOW_SECONDS = 600

WEB, DB_SRV, FILE_SRV, BASTION = "10.0.2.10", "10.0.2.20", "10.0.2.30", "10.0.2.40"
_SERVER_PORTS = {WEB: (80, 443), DB_SRV: (5432,), FILE_SRV: (445,), BASTION: (22,)}
_WORKSTATIONS = [f"10.0.1.{n}" for n in range(11, 31)]
_DOC_ADDRESSES = [f"{p}.{n}" for p in ("192.0.2", "198.51.100", "203.0.113") for n in range(1, 255)]
_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433,
                 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017, 11211]
_FLOW_COLUMNS = ["ts", "src", "dst", "dst_port", "proto", "bytes", "packets",
                 "failed_logins", "truth"]
DEFAULT_START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def is_internal(ip: str) -> bool:
    return ip.startswith("10.")


def _flows(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=_FLOW_COLUMNS)


def generate_benign_flows(seed: int, start: datetime = DEFAULT_START, n: int = 600) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    externals = list(rng.choice(_DOC_ADDRESSES, 10, replace=False))
    visitors = list(rng.choice(_DOC_ADDRESSES, 60, replace=False))
    rows = []
    for _ in range(n):
        ts = start + timedelta(seconds=float(rng.uniform(0, WINDOW_SECONDS)))
        roll = rng.random()
        if roll < 0.45:                                       # workstation -> internal server
            src = str(rng.choice(_WORKSTATIONS))
            dst = str(rng.choice(list(_SERVER_PORTS)))
            port = int(rng.choice(_SERVER_PORTS[dst]))
            nbytes = int(min(rng.lognormal(10.8, 1.2), 5_000_000))
            fails = int(rng.random() < 0.05) if port == 22 else 0
            rows.append(dict(ts=ts, src=src, dst=dst, dst_port=port, proto="TCP", bytes=nbytes,
                             packets=max(2, nbytes // 900), failed_logins=fails, truth="benign"))
        elif roll < 0.75:                                     # workstation -> external peer
            nbytes = int(min(rng.lognormal(11.5, 1.0), 2_000_000))
            rows.append(dict(ts=ts, src=str(rng.choice(_WORKSTATIONS)), dst=str(rng.choice(externals)),
                             dst_port=443, proto="TCP", bytes=nbytes,
                             packets=max(2, nbytes // 900), failed_logins=0, truth="benign"))
        else:                                                 # external visitor -> web server
            nbytes = int(min(rng.lognormal(9.5, 0.8), 300_000))
            rows.append(dict(ts=ts, src=str(rng.choice(visitors)), dst=WEB, dst_port=443,
                             proto="TCP", bytes=nbytes, packets=int(min(max(2, nbytes // 900), 300)),
                             failed_logins=0, truth="benign"))
    return _flows(rows)


def inject_attack(flows: pd.DataFrame, kind: str, seed: int,
                  start: datetime = DEFAULT_START) -> pd.DataFrame:
    """Append synthetic attack-pattern rows to a flow table (just rows, nothing is sent)."""
    if kind == "Normal traffic":
        return flows
    if kind not in CYBER_SCENARIOS:
        raise ValueError(f"Unknown cyber scenario: {kind}")
    rng = np.random.default_rng(seed + 7919)
    t0 = start + timedelta(seconds=float(rng.uniform(120, 420)))
    rows = []
    used = set(flows["src"]) | set(flows["dst"])     # attacker addresses must be new ones
    fresh = [a for a in _DOC_ADDRESSES if a not in used]

    def pick(prefix: str) -> str:
        options = [a for a in fresh if a.startswith(prefix)]
        return str(rng.choice(options))
    if kind == "Port scan":
        src = pick("198.51.100.")
        for port in rng.choice(_COMMON_PORTS, 25, replace=False):
            rows.append(dict(ts=t0 + timedelta(seconds=float(rng.uniform(0, 30))), src=src, dst=WEB,
                             dst_port=int(port), proto="TCP", bytes=60, packets=int(rng.integers(1, 4)),
                             failed_logins=0, truth=kind))
    elif kind == "Brute force":
        src = pick("203.0.113.")
        for _ in range(30):
            rows.append(dict(ts=t0 + timedelta(seconds=float(rng.uniform(0, 90))), src=src, dst=BASTION,
                             dst_port=22, proto="TCP", bytes=int(rng.integers(900, 2500)),
                             packets=int(rng.integers(8, 20)), failed_logins=int(rng.integers(1, 4)),
                             truth=kind))
    elif kind == "Data exfiltration":
        src = str(rng.choice(_WORKSTATIONS))
        dst = pick("192.0.2.")
        for _ in range(6):
            nbytes = int(rng.integers(18_000_000, 25_000_000))
            rows.append(dict(ts=t0 + timedelta(seconds=float(rng.uniform(0, 120))), src=src, dst=dst,
                             dst_port=443, proto="TCP", bytes=nbytes, packets=nbytes // 1200,
                             failed_logins=0, truth=kind))
    elif kind == "Traffic flood":
        for src in rng.choice(fresh, 45, replace=False):
            packets = int(rng.integers(25_000, 60_000))
            rows.append(dict(ts=t0 + timedelta(seconds=float(rng.uniform(0, 40))), src=str(src), dst=WEB,
                             dst_port=80, proto="TCP", bytes=packets * 60, packets=packets,
                             failed_logins=0, truth=kind))
    return pd.concat([flows, _flows(rows)], ignore_index=True)


def build_cyber_scenario(seed: int, scenario: str = "Normal traffic",
                         start: datetime = DEFAULT_START) -> pd.DataFrame:
    flows = inject_attack(generate_benign_flows(seed, start), scenario, seed, start)
    return flows.sort_values("ts").reset_index(drop=True)


def detect_cyber(flows: pd.DataFrame) -> tuple[list[dict], pd.DataFrame]:
    """Apply the four rules. Ignores the 'truth' column. Returns (detections, labelled flows)."""
    df = flows.copy()
    df["detected"] = "benign"
    dets: list[dict] = []
    if df.empty:
        return dets, df

    # Rule 1: port scan - one source touches >= 15 distinct ports on one host
    for (src, dst), g in df.groupby(["src", "dst"]):
        if g["dst_port"].nunique() >= PORT_SCAN_MIN_PORTS:
            df.loc[g.index, "detected"] = "Port scan"
            dets.append({"kind": "PORT_SCAN", "severity": "MEDIUM", "source": src,
                         "title": f"Port scan from {src}",
                         "details": f"{src} probed {g['dst_port'].nunique()} ports on {dst}."})

    # Rule 2: brute force - >= 20 failed SSH/RDP logins from one source against one host
    remote = df[df["dst_port"].isin([22, 3389])]
    for (src, dst), g in remote.groupby(["src", "dst"]):
        if g["failed_logins"].sum() >= BRUTE_FORCE_MIN_FAILS:
            df.loc[g.index, "detected"] = "Brute force"
            dets.append({"kind": "BRUTE_FORCE", "severity": "HIGH", "source": src,
                         "title": f"Brute-force login attempts from {src}",
                         "details": f"{int(g['failed_logins'].sum())} failed logins from {src} "
                                    f"to {dst} (ports 22/3389)."})

    # Rule 3: exfiltration - >= 50 MB from an internal host to one external address
    outbound = df[df["src"].map(is_internal) & ~df["dst"].map(is_internal)]
    for (src, dst), g in outbound.groupby(["src", "dst"]):
        if g["bytes"].sum() >= EXFIL_MIN_BYTES:
            df.loc[g.index, "detected"] = "Data exfiltration"
            dets.append({"kind": "DATA_EXFILTRATION", "severity": "CRITICAL", "source": src,
                         "title": f"Possible data exfiltration from {src}",
                         "details": f"{g['bytes'].sum() / 1e6:.0f} MB sent from {src} to {dst}."})

    # Rule 4: flood - >= 30 external sources, each >= 20,000 packets, to one host
    heavy = df[~df["src"].map(is_internal) & (df["packets"] >= FLOOD_MIN_PACKETS)]
    for dst, g in heavy.groupby("dst"):
        if g["src"].nunique() >= FLOOD_MIN_SOURCES:
            df.loc[g.index, "detected"] = "Traffic flood"
            dets.append({"kind": "TRAFFIC_FLOOD", "severity": "HIGH", "source": f"{g['src'].nunique()} sources",
                         "title": f"Traffic flood against {dst}",
                         "details": f"{g['src'].nunique()} external sources sent heavy traffic to {dst}."})
    for d in dets:
        d["source"] = str(d["source"])
    return dets, df


# =====================================================================
# 3. RADAR
# =====================================================================
RANGE_KM = 100.0
STEP_SECONDS = 60                 # simulated seconds per radar step
RESTRICTED_ZONE = (30.0, 20.0, 15.0)   # centre x km, centre y km, radius km
TRAIL_LENGTH = 12
SWEEP_DEG_PER_STEP = 20

# callsign, kind, IFF, x km, y km, heading deg (compass), speed km/h
_BASE_TRACKS = (
    ("SIA212", "AIRLINER", "CIVIL", -85, 40, 100, 840),
    ("DLH88", "AIRLINER", "CIVIL", 70, -60, 300, 820),
    ("UAE505", "AIRLINER", "CIVIL", 10, 90, 190, 850),
    ("N431LP", "LIGHT AIRCRAFT", "CIVIL", -30, -40, 45, 230),
    ("G-SKYE", "LIGHT AIRCRAFT", "CIVIL", 50, 50, 270, 210),
    ("RESCUE7", "HELICOPTER", "FRIEND", 5, -10, 20, 170),
    ("HELO-2", "HELICOPTER", "FRIEND", -20, 25, 120, 160),
    ("PATROL1", "VESSEL", "FRIEND", 40, -70, 330, 45),
    ("MV Aurora", "VESSEL", "CIVIL", -60, -20, 80, 25),
    ("MV Kestrel", "VESSEL", "CIVIL", 60, 10, 200, 20),
    ("FV Dawn", "VESSEL", "CIVIL", -45, 60, 160, 15),
    ("UNK-V1", "VESSEL", "UNKNOWN", -60, -50, 200, 20),
)


def in_zone(x: float, y: float, zone=RESTRICTED_ZONE) -> bool:
    return math.hypot(x - zone[0], y - zone[1]) <= zone[2]


def bearing_deg(x: float, y: float) -> float:
    return math.degrees(math.atan2(x, y)) % 360.0


class RadarSim:
    """A virtual radar picture. Positions are km east (x) and north (y) of the radar."""

    def __init__(self, seed: int = 0):
        self.seed = seed
        self.rng = np.random.default_rng(seed)
        self.steps = 0
        self._counter = 100
        self.tracks: list[dict] = []
        self.alerted: set[str] = set()
        self._inside: set[str] = set()
        for call, kind, iff, x, y, hdg, spd in _BASE_TRACKS:
            jx, jy = self.rng.uniform(-1, 1, 2)
            self._add_track(call, kind, iff, x + jx, y + jy, hdg, spd)

    # -- helpers
    def _add_track(self, call, kind, iff, x, y, hdg, spd) -> dict:
        track = {"id": call, "kind": kind, "iff": iff, "x": float(x), "y": float(y),
                 "heading": float(hdg), "speed_kmh": float(spd), "trail": [(float(x), float(y))]}
        self.tracks.append(track)
        if iff == "UNKNOWN" and in_zone(x, y):
            self._inside.add(call)
            self.alerted.add(call)          # started inside: no "entry" to report
        return track

    @property
    def sweep_angle(self) -> float:
        return (self.steps * SWEEP_DEG_PER_STEP) % 360.0

    def inject_unknown(self) -> str:
        """Add an unidentified aircraft that flies straight at the restricted zone."""
        self._counter += 1
        bearing = math.radians(float(self.rng.uniform(0, 360)))
        x, y = 92.0 * math.sin(bearing), 92.0 * math.cos(bearing)
        zx, zy, zr = RESTRICTED_ZONE
        tx, ty = zx + self.rng.uniform(-3, 3), zy + self.rng.uniform(-3, 3)
        heading = bearing_deg(tx - x, ty - y)
        track = self._add_track(f"UNK-{self._counter}", "AIRCRAFT", "UNKNOWN", x, y, heading, 450.0)
        return track["id"]

    def step(self, n: int = 1) -> list[dict]:
        """Advance n steps. Returns one entry dict per unidentified track that newly
        crossed into the restricted zone (each track is reported at most once)."""
        entries: list[dict] = []
        for _ in range(n):
            self.steps += 1
            for t in self.tracks:
                dist = t["speed_kmh"] * STEP_SECONDS / 3600.0
                h = math.radians(t["heading"])
                t["x"] += dist * math.sin(h)
                t["y"] += dist * math.cos(h)
                r = math.hypot(t["x"], t["y"])
                if r > RANGE_KM:        # left the picture: re-enter on the far side
                    scale = (RANGE_KM - 1.0) / r
                    t["x"], t["y"] = -t["x"] * scale, -t["y"] * scale
                    t["trail"] = []
                t["trail"].append((t["x"], t["y"]))
                t["trail"] = t["trail"][-TRAIL_LENGTH:]
                if t["iff"] == "UNKNOWN":
                    inside = in_zone(t["x"], t["y"])
                    if inside and t["id"] not in self._inside and t["id"] not in self.alerted:
                        self.alerted.add(t["id"])
                        entries.append({"id": t["id"], "x": t["x"], "y": t["y"],
                                        "range_km": math.hypot(t["x"], t["y"]),
                                        "bearing_deg": bearing_deg(t["x"], t["y"])})
                    (self._inside.add if inside else self._inside.discard)(t["id"])
        return entries

    def snapshot(self) -> pd.DataFrame:
        rows = [{"id": t["id"], "kind": t["kind"], "iff": t["iff"],
                 "range_km": round(math.hypot(t["x"], t["y"]), 1),
                 "bearing_deg": round(bearing_deg(t["x"], t["y"]), 1),
                 "speed_kmh": round(t["speed_kmh"]), "heading_deg": round(t["heading"]),
                 "in_restricted_zone": in_zone(t["x"], t["y"]), "x": t["x"], "y": t["y"]}
                for t in self.tracks]
        return pd.DataFrame(rows)
