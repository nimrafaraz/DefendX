"""Business logic that connects simulators to the event store (with permission checks)."""
from __future__ import annotations

import secrets
from datetime import timedelta

import numpy as np

from . import audit, auth, config, events
from . import simulation as sim
from .timeutil import to_iso, utcnow


def require(user: dict | None, permission: str) -> None:
    if not user or not auth.has_permission(user.get("role"), permission):
        raise PermissionError(f"Your role is not allowed to do this ({permission}).")


def _new_seed() -> int:
    return secrets.randbelow(1_000_000)


# ------------------------------------------------------------------ scans
def run_rf_scan(user: dict, scenario: str, seed: int | None = None) -> dict:
    require(user, "run_simulations")
    seed = _new_seed() if seed is None else seed
    sweep = sim.simulate_sweep(seed, scenario)
    detections = sim.detect_rf(sweep["freqs"], sweep["power_dbm"])
    ids = [events.add_event("RF", d["severity"], d["title"], d["details"], d["source"])
           for d in detections]
    audit.log(user["id"], "SCAN_RF", f"scenario={scenario} seed={seed} detections={len(detections)}")
    return {"sweep": sweep, "detections": detections, "event_ids": ids, "seed": seed}


def run_cyber_scan(user: dict, scenario: str, seed: int | None = None) -> dict:
    require(user, "run_simulations")
    seed = _new_seed() if seed is None else seed
    start = utcnow() - timedelta(minutes=10)
    flows = sim.build_cyber_scenario(seed, scenario, start)
    detections, labelled = sim.detect_cyber(flows)
    ids = [events.add_event("CYBER", d["severity"], d["title"], d["details"], d["source"])
           for d in detections]
    audit.log(user["id"], "SCAN_CYBER", f"scenario={scenario} seed={seed} detections={len(detections)}")
    return {"flows": labelled, "detections": detections, "event_ids": ids, "seed": seed}


def log_radar_zone_entries(user: dict, entries: list[dict]) -> list[int]:
    """Write one HIGH event per newly detected restricted-zone entry."""
    require(user, "run_simulations")
    ids = []
    for e in entries:
        ids.append(events.add_event(
            "RADAR", "HIGH", f"Unidentified track {e['id']} entered restricted zone",
            f"Range {e['range_km']:.1f} km, bearing {e['bearing_deg']:.0f} deg, IFF UNKNOWN.",
            "Radar PPI"))
        audit.log(user["id"], "RADAR_ZONE_ALERT", f"track={e['id']}")
    return ids


def inject_scenario(user: dict) -> dict:
    """One-click demo: related RF, CYBER and RADAR events in the same few minutes."""
    require(user, "run_simulations")
    seed = _new_seed()
    rf = run_rf_scan(user, "Unknown emitter", seed)
    cy1 = run_cyber_scan(user, "Port scan", seed + 1)
    cy2 = run_cyber_scan(user, "Data exfiltration", seed + 2)
    radar = sim.RadarSim(seed)
    track = radar.inject_unknown()
    entries = []
    for _ in range(40):
        entries = radar.step()
        if entries:
            break
    radar_ids = log_radar_zone_entries(user, entries)
    all_ids = rf["event_ids"] + cy1["event_ids"] + cy2["event_ids"] + radar_ids
    audit.log(user["id"], "SCENARIO_INJECTED", f"seed={seed} events={len(all_ids)} track={track}")
    return {"event_ids": all_ids, "seed": seed}


# ------------------------------------------------------------ event actions
def acknowledge_event(user: dict, event_id: int) -> None:
    require(user, "manage_events")
    events.set_status(event_id, "ACKNOWLEDGED")
    audit.log(user["id"], "EVENT_ACKNOWLEDGED", f"event_id={event_id}")


def resolve_event(user: dict, event_id: int) -> None:
    require(user, "manage_events")
    events.set_status(event_id, "RESOLVED")
    audit.log(user["id"], "EVENT_RESOLVED", f"event_id={event_id}")


# ------------------------------------------------------------ demo history
_RF_TEMPLATES = (
    ("Unknown emitter at {f:.1f} MHz", "HIGH", "Peak matches no authorised emitter.", "RF sweep 400-470 MHz"),
    ("Power deviation on Logistics Net", "MEDIUM", "Level moved more than 8 dB from baseline.", "RF sweep 400-470 MHz"),
    ("Emitter offline: Telemetry Beta", "MEDIUM", "No signal near planned 452.0 MHz.", "RF sweep 400-470 MHz"),
    ("Broadband noise-floor rise", "LOW", "Median level above the noise floor.", "RF sweep 400-470 MHz"),
)
_CYBER_TEMPLATES = (
    ("Port scan from {ip}", "MEDIUM", "Many ports probed on the web server.", "{ip}"),
    ("Brute-force login attempts from {ip}", "HIGH", "Repeated failed SSH logins.", "{ip}"),
    ("Possible data exfiltration from 10.0.1.{w}", "CRITICAL", "Large outbound transfer to one external address.", "10.0.1.{w}"),
    ("Traffic flood against 10.0.2.10", "HIGH", "Many external sources sent heavy traffic.", "45 sources"),
    ("Unusual DNS query volume", "LOW", "Query rate above the usual pattern.", "10.0.1.{w}"),
)
_RADAR_TEMPLATES = (
    ("Unidentified track UNK-{n} entered restricted zone", "HIGH", "IFF UNKNOWN inside the zone.", "Radar PPI"),
    ("IFF mismatch on track N431LP", "MEDIUM", "Transponder code changed.", "Radar PPI"),
    ("Track lost: MV Kestrel", "LOW", "No return for three sweeps.", "Radar PPI"),
)
_RISK_RANGE = {"LOW": (10, 30), "MEDIUM": (31, 55), "HIGH": (56, 80), "CRITICAL": (81, 98)}


def _make_event(rng, domain, ts, status):
    template = {"RF": _RF_TEMPLATES, "CYBER": _CYBER_TEMPLATES, "RADAR": _RADAR_TEMPLATES}[domain]
    title, sev, details, source = template[int(rng.integers(len(template)))]
    fill = dict(f=float(rng.uniform(401, 469)), ip=f"198.51.100.{int(rng.integers(2, 250))}",
                w=int(rng.integers(11, 31)), n=int(rng.integers(101, 140)))
    lo, hi = _RISK_RANGE[sev]
    events.add_event(domain, sev, title.format(**fill), details, source.format(**fill),
                     risk_score=float(rng.integers(lo, hi + 1)), status=status, ts=to_iso(ts))


def seed_demo_history(hours: int = config.DEMO_HISTORY_HOURS, seed: int = 2026, now=None) -> int:
    """Replace all events with `hours` of synthetic history. Returns the number created."""
    now = now or utcnow()
    rng = np.random.default_rng(seed)
    events.clear_events()
    created = 0

    def status_for(age_hours: float) -> str:
        if age_hours < 6:
            return "OPEN" if rng.random() < 0.8 else "ACKNOWLEDGED"
        roll = rng.random()
        return "RESOLVED" if roll < 0.8 else "ACKNOWLEDGED" if roll < 0.95 else "OPEN"

    for _ in range(70):                                           # background noise
        age = float(rng.uniform(0.2, hours))
        domain = str(rng.choice(config.DOMAINS, p=[0.30, 0.45, 0.25]))
        _make_event(rng, domain, now - timedelta(hours=age), status_for(age))
        created += 1

    for age in (0.7, 5.0, 17.0, 30.0):                            # cross-domain clusters
        base = now - timedelta(hours=age)
        status = "OPEN" if age < 6 else "RESOLVED"
        for offset, domain in zip((0, 3, 6), ("RF", "CYBER", "RADAR")):
            _make_event(rng, domain, base + timedelta(minutes=offset + float(rng.uniform(0, 1))), status)
            created += 1
    return created


def ensure_demo_data() -> None:
    """First-run set-up: demo accounts plus 48 h of history if the event store is empty."""
    auth.seed_demo_users()
    if events.count_events() == 0:
        seed_demo_history()
