import unittest

import numpy as np

from defendx import simulation as sim


class RfTests(unittest.TestCase):
    def detect(self, seed, scenario):
        sw = sim.simulate_sweep(seed, scenario)
        return sim.detect_rf(sw["freqs"], sw["power_dbm"])

    def test_sweep_shape_and_range(self):
        sw = sim.simulate_sweep(1)
        self.assertEqual(len(sw["freqs"]), 701)
        self.assertEqual(sw["freqs"][0], 400.0)
        self.assertEqual(sw["freqs"][-1], 470.0)
        self.assertEqual(len(sw["power_dbm"]), 701)

    def test_same_seed_same_sweep_different_seed_differs(self):
        a, b, c = (sim.simulate_sweep(s)["power_dbm"] for s in (5, 5, 6))
        self.assertTrue(np.array_equal(a, b))
        self.assertFalse(np.array_equal(a, c))

    def test_no_false_positives_on_normal_sweeps(self):
        for seed in range(150):
            self.assertEqual(self.detect(seed, "Normal"), [], f"seed {seed}")

    def test_unknown_emitter_detected_as_high(self):
        for seed in range(40):
            d = self.detect(seed, "Unknown emitter")
            self.assertEqual([x["kind"] for x in d], ["UNKNOWN_EMITTER"])
            self.assertEqual(d[0]["severity"], "HIGH")
            self.assertAlmostEqual(d[0]["freq_mhz"], 444.7, delta=0.3)

    def test_power_deviation_detected(self):
        for seed in range(40):
            d = self.detect(seed, "Power deviation")
            self.assertEqual([x["kind"] for x in d], ["POWER_DEVIATION"])
            self.assertIn("Logistics Net", d[0]["title"])

    def test_offline_emitter_detected(self):
        for seed in range(40):
            d = self.detect(seed, "Offline emitter")
            self.assertEqual([x["kind"] for x in d], ["EMITTER_OFFLINE"])
            self.assertIn("Telemetry Beta", d[0]["title"])

    def test_noise_floor_rise_detected_without_other_alerts(self):
        for seed in range(40):
            d = self.detect(seed, "Noise floor rise")
            self.assertEqual([x["kind"] for x in d], ["NOISE_FLOOR_RISE"])

    def test_unknown_emitter_severity_grading(self):
        freqs = sim.FREQS
        for power, expected in ((-55, "HIGH"), (-70, "MEDIUM"), (-80, "LOW")):
            p = np.full(len(freqs), -105.0)
            for e in sim.AUTHORISED_EMITTERS:
                p[np.abs(freqs - e["freq_mhz"]) < 0.05] = e["power_dbm"]
            p[np.abs(freqs - 444.7) < 0.05] = power
            kinds = {(x["kind"], x["severity"]) for x in sim.detect_rf(freqs, p)}
            self.assertIn(("UNKNOWN_EMITTER", expected), kinds)

    def test_waterfall_shape_and_determinism(self):
        w1 = sim.simulate_waterfall(3, "Unknown emitter")
        w2 = sim.simulate_waterfall(3, "Unknown emitter")
        self.assertEqual(w1.shape, (30, 701))
        self.assertTrue(np.array_equal(w1, w2))

    def test_unknown_scenario_rejected(self):
        with self.assertRaises(ValueError):
            sim.simulate_sweep(1, "Nonsense")


class CyberTests(unittest.TestCase):
    def detect(self, seed, scenario):
        return sim.detect_cyber(sim.build_cyber_scenario(seed, scenario))

    def test_deterministic(self):
        a = sim.build_cyber_scenario(4, "Port scan")
        b = sim.build_cyber_scenario(4, "Port scan")
        self.assertTrue(a.equals(b))

    def test_external_addresses_use_documentation_ranges_only(self):
        for scenario in sim.CYBER_SCENARIOS:
            df = sim.build_cyber_scenario(2, scenario)
            ips = set(df["src"]) | set(df["dst"])
            for ip in ips:
                if not sim.is_internal(ip):
                    self.assertTrue(ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), ip)

    def test_no_false_positives_on_normal_traffic(self):
        for seed in range(60):
            dets, labelled = self.detect(seed, "Normal traffic")
            self.assertEqual(dets, [], f"seed {seed}")
            self.assertTrue((labelled["detected"] == "benign").all())

    def _check(self, scenario, kind, label, severity):
        for seed in range(40):
            dets, labelled = self.detect(seed, scenario)
            self.assertEqual([d["kind"] for d in dets], [kind], f"seed {seed}")
            self.assertEqual(dets[0]["severity"], severity)
            # every attack row is labelled, and no benign row is
            self.assertEqual(set(labelled.loc[labelled["truth"] != "benign", "detected"]), {label})
            self.assertTrue((labelled.loc[labelled["truth"] == "benign", "detected"] == "benign").all())

    def test_port_scan(self):
        self._check("Port scan", "PORT_SCAN", "Port scan", "MEDIUM")

    def test_brute_force(self):
        self._check("Brute force", "BRUTE_FORCE", "Brute force", "HIGH")

    def test_exfiltration(self):
        self._check("Data exfiltration", "DATA_EXFILTRATION", "Data exfiltration", "CRITICAL")

    def test_flood(self):
        self._check("Traffic flood", "TRAFFIC_FLOOD", "Traffic flood", "HIGH")

    def test_detector_ignores_truth_column(self):
        df = sim.build_cyber_scenario(9, "Port scan").drop(columns=["truth"])
        dets, _ = sim.detect_cyber(df)
        self.assertEqual([d["kind"] for d in dets], ["PORT_SCAN"])

    def test_thresholds_just_below_do_not_fire(self):
        base = sim.generate_benign_flows(1)
        rows = [dict(ts=sim.DEFAULT_START, src="198.51.100.9", dst=sim.WEB, dst_port=1000 + i,
                     proto="TCP", bytes=60, packets=1, failed_logins=0, truth="x")
                for i in range(sim.PORT_SCAN_MIN_PORTS - 1)]
        import pandas as pd
        dets, _ = sim.detect_cyber(pd.concat([base, pd.DataFrame(rows)], ignore_index=True))
        self.assertEqual(dets, [])

    def test_unknown_scenario_rejected(self):
        with self.assertRaises(ValueError):
            sim.build_cyber_scenario(1, "Nonsense")


class RadarTests(unittest.TestCase):
    def test_twelve_base_tracks_one_unknown(self):
        r = sim.RadarSim(0)
        df = r.snapshot()
        self.assertEqual(len(df), 12)
        self.assertEqual((df["iff"] == "UNKNOWN").sum(), 1)

    def test_deterministic(self):
        a, b = sim.RadarSim(7), sim.RadarSim(7)
        a.inject_unknown(); b.inject_unknown()
        a.step(15); b.step(15)
        self.assertTrue(a.snapshot().equals(b.snapshot()))

    def test_tracks_stay_inside_picture_and_trails_are_bounded(self):
        r = sim.RadarSim(3)
        for _ in range(200):
            r.step()
            for t in r.tracks:
                self.assertLessEqual((t["x"] ** 2 + t["y"] ** 2) ** 0.5, sim.RANGE_KM + 1e-6)
                self.assertLessEqual(len(t["trail"]), sim.TRAIL_LENGTH)

    def test_no_alert_without_an_intruder(self):
        r = sim.RadarSim(1)
        self.assertEqual(r.step(60), [])

    def test_injected_unknown_triggers_exactly_one_alert(self):
        for seed in range(10):
            r = sim.RadarSim(seed)
            tid = r.inject_unknown()
            entries = r.step(80)                     # long enough to cross and leave
            self.assertEqual([e["id"] for e in entries], [tid], f"seed {seed}")

    def test_known_tracks_never_alert_even_inside_zone(self):
        r = sim.RadarSim(2)
        helo = next(t for t in r.tracks if t["id"] == "RESCUE7")
        helo["x"], helo["y"] = sim.RESTRICTED_ZONE[0], sim.RESTRICTED_ZONE[1]
        self.assertEqual(r.step(3), [])

    def test_track_starting_inside_zone_is_not_reported_as_entry(self):
        r = sim.RadarSim(2)
        zx, zy, _ = sim.RESTRICTED_ZONE
        r._add_track("UNK-X", "AIRCRAFT", "UNKNOWN", zx, zy, 90, 1)
        self.assertEqual(r.step(1), [])


if __name__ == "__main__":
    unittest.main()
