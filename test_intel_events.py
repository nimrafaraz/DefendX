import unittest
from datetime import timedelta

from defendx import audit, auth, config, events, intel, services
from defendx.timeutil import to_iso, utcnow
from tests.helpers import TempDataCase

T0 = utcnow().replace(minute=0, second=0)


def ev(i, domain, risk, minutes=0, status="OPEN", severity="HIGH"):
    return {"id": i, "ts": to_iso(T0 + timedelta(minutes=minutes)), "domain": domain,
            "severity": severity, "title": f"event {i}", "status": status, "risk_score": risk}


class ScoringTests(unittest.TestCase):
    def test_no_events_scores_zero_low(self):
        self.assertEqual(intel.overall_score([]), 0.0)
        self.assertEqual(intel.risk_level(0), "LOW")

    def test_level_boundaries(self):
        cases = {0: "LOW", 24.9: "LOW", 25: "MEDIUM", 49.9: "MEDIUM",
                 50: "HIGH", 74.9: "HIGH", 75: "CRITICAL", 100: "CRITICAL"}
        for score, level in cases.items():
            self.assertEqual(intel.risk_level(score), level, score)

    def test_single_event_formula(self):
        # 0.6*50 + 0.4*50 = 50; one domain -> no extra; volume 5*1/20 = 0.25
        self.assertEqual(intel.overall_score([ev(1, "RF", 50)]), 50.2)  # rounded to 1 decimal

    def test_extra_serious_domains_add_six_each(self):
        one = intel.overall_score([ev(1, "RF", 60), ev(2, "RF", 60)])
        three = intel.overall_score([ev(1, "RF", 60), ev(2, "CYBER", 60), ev(3, "RADAR", 60)])
        self.assertAlmostEqual(three - one, 12 + (5 * 3 / 20) - (5 * 2 / 20), places=1)

    def test_low_risk_domains_do_not_count_as_serious(self):
        base = intel.overall_score([ev(1, "RF", 60)])
        plus = intel.overall_score([ev(1, "RF", 60), ev(2, "CYBER", 20)])
        self.assertLess(plus - base, 6)

    def test_resolved_events_are_ignored(self):
        self.assertEqual(intel.overall_score([ev(1, "RF", 90, status="RESOLVED")]), 0.0)

    def test_acknowledged_events_still_count(self):
        self.assertGreater(intel.overall_score([ev(1, "RF", 90, status="ACKNOWLEDGED")]), 80)

    def test_volume_bonus_capped_at_five(self):
        many = [ev(i, "RF", 10) for i in range(100)]
        self.assertAlmostEqual(intel.overall_score(many), 10 + 5, places=1)

    def test_score_capped_at_100(self):
        many = [ev(i, d, 99) for i, d in enumerate(["RF", "CYBER", "RADAR"] * 10)]
        self.assertEqual(intel.overall_score(many), 100.0)


class CorrelationTests(unittest.TestCase):
    def test_two_domains_within_window_make_an_incident(self):
        inc = intel.correlate([ev(1, "RF", 70, 0), ev(2, "CYBER", 60, 5)], 10)
        self.assertEqual(len(inc), 1)
        self.assertEqual(inc[0]["domains"], ["CYBER", "RF"])
        self.assertEqual(inc[0]["event_ids"], [1, 2])

    def test_events_outside_window_do_not_correlate(self):
        self.assertEqual(intel.correlate([ev(1, "RF", 70, 0), ev(2, "CYBER", 60, 30)], 10), [])

    def test_same_domain_never_makes_an_incident(self):
        self.assertEqual(intel.correlate([ev(1, "RF", 70, 0), ev(2, "RF", 60, 2)], 10), [])

    def test_window_is_configurable(self):
        evs = [ev(1, "RF", 70, 0), ev(2, "CYBER", 60, 20)]
        self.assertEqual(intel.correlate(evs, 10), [])
        self.assertEqual(len(intel.correlate(evs, 30)), 1)

    def test_incidents_ordered_by_time_with_sequential_ids(self):
        evs = [ev(4, "RF", 70, 100), ev(5, "RADAR", 60, 102),
               ev(1, "RF", 70, 0), ev(2, "CYBER", 60, 3)]            # given out of order
        inc = intel.correlate(evs, 10)
        self.assertEqual([i["id"] for i in inc], ["INC-001", "INC-002"])
        self.assertLess(inc[0]["start"], inc[1]["start"])

    def test_overlapping_windows_do_not_create_duplicate_incidents(self):
        evs = [ev(1, "RF", 70, 0), ev(2, "CYBER", 60, 2), ev(3, "RADAR", 60, 4)]
        self.assertEqual(len(intel.correlate(evs, 10)), 1)

    def test_incident_score_includes_cross_domain_bonus(self):
        inc = intel.correlate([ev(1, "RF", 80, 0), ev(2, "CYBER", 60, 1), ev(3, "RADAR", 40, 2)], 10)[0]
        expected = 0.6 * 80 + 0.4 * 60 + 5 * 2
        self.assertAlmostEqual(inc["score"], expected, places=1)

    def test_active_flag_and_filters(self):
        resolved = intel.correlate([ev(1, "RF", 70, 0, "RESOLVED"), ev(2, "CYBER", 60, 1, "RESOLVED")], 10)
        live = intel.correlate([ev(3, "RF", 70, 0), ev(4, "CYBER", 60, 1, "RESOLVED")], 10)
        self.assertFalse(resolved[0]["active"])
        self.assertTrue(live[0]["active"])
        self.assertEqual(intel.active_incidents(resolved + live), live)

    def test_strongest_sorted_by_score(self):
        a = intel.correlate([ev(1, "RF", 90, 0), ev(2, "CYBER", 90, 1)], 10)
        b = intel.correlate([ev(3, "RF", 20, 100), ev(4, "CYBER", 20, 101)], 10)
        top = intel.strongest(b + a, 1)
        self.assertEqual(top[0]["score"], a[0]["score"])


class EventStoreTests(TempDataCase):
    def test_add_and_get_with_default_risk(self):
        eid = events.add_event("RF", "HIGH", "Test", "details", "src")
        e = events.get_event(eid)
        self.assertEqual((e["domain"], e["severity"], e["status"]), ("RF", "HIGH", "OPEN"))
        self.assertEqual(e["risk_score"], config.SEVERITY_RISK["HIGH"])

    def test_validation(self):
        for args in (("BAD", "HIGH", "t"), ("RF", "BAD", "t"), ("RF", "HIGH", "  ")):
            with self.assertRaises(ValueError):
                events.add_event(*args)
        with self.assertRaises(ValueError):
            events.add_event("RF", "HIGH", "t", status="BAD")

    def test_risk_score_clamped(self):
        eid = events.add_event("RF", "LOW", "t", risk_score=500)
        self.assertEqual(events.get_event(eid)["risk_score"], 100.0)

    def test_filters_and_status_changes(self):
        a = events.add_event("RF", "HIGH", "a")
        b = events.add_event("CYBER", "LOW", "b")
        events.set_status(a, "RESOLVED")
        self.assertEqual([e["id"] for e in events.list_events(domain="CYBER")], [b])
        self.assertEqual([e["id"] for e in events.list_events(unresolved_only=True)], [b])
        self.assertEqual(events.count_events(), 2)
        self.assertEqual(events.count_events(unresolved_only=True), 1)
        with self.assertRaises(ValueError):
            events.set_status(a, "BAD")
        with self.assertRaises(ValueError):
            events.set_status(9999, "OPEN")


class ServicesTests(TempDataCase):
    def setUp(self):
        super().setUp()
        self.operator = auth.create_user("oper", "Passw0rdO", "OPERATOR")
        self.analyst = auth.create_user("anal", "Passw0rdA", "ANALYST")
        self.viewer = auth.create_user("view", "Passw0rdV", "VIEWER")

    def test_rf_scan_logs_events_and_audit(self):
        res = services.run_rf_scan(self.operator, "Unknown emitter", seed=11)
        self.assertEqual(len(res["event_ids"]), 1)
        e = events.get_event(res["event_ids"][0])
        self.assertEqual((e["domain"], e["severity"]), ("RF", "HIGH"))
        self.assertIn("SCAN_RF", {a["action"] for a in audit.recent()})

    def test_normal_scans_log_nothing(self):
        services.run_rf_scan(self.operator, "Normal", seed=1)
        services.run_cyber_scan(self.operator, "Normal traffic", seed=1)
        self.assertEqual(events.count_events(), 0)

    def test_each_cyber_pattern_logs_one_matching_event(self):
        expected = {"Port scan": "Port scan", "Brute force": "Brute-force",
                    "Data exfiltration": "exfiltration", "Traffic flood": "flood"}
        for scenario, word in expected.items():
            before = events.count_events(domain="CYBER")
            res = services.run_cyber_scan(self.operator, scenario, seed=5)
            self.assertEqual(len(res["event_ids"]), 1, scenario)
            self.assertEqual(events.count_events(domain="CYBER"), before + 1)
            self.assertIn(word, events.get_event(res["event_ids"][0])["title"])

    def test_permissions_enforced(self):
        for user in (self.analyst, self.viewer):
            with self.assertRaises(PermissionError):
                services.run_rf_scan(user, "Normal")
            with self.assertRaises(PermissionError):
                services.run_cyber_scan(user, "Normal traffic")
            with self.assertRaises(PermissionError):
                services.inject_scenario(user)
        with self.assertRaises(PermissionError):
            services.acknowledge_event(self.viewer, 1)
        with self.assertRaises(PermissionError):
            services.run_rf_scan(None, "Normal")

    def test_acknowledge_and_resolve(self):
        eid = events.add_event("RF", "HIGH", "x")
        services.acknowledge_event(self.analyst, eid)
        self.assertEqual(events.get_event(eid)["status"], "ACKNOWLEDGED")
        services.resolve_event(self.operator, eid)
        self.assertEqual(events.get_event(eid)["status"], "RESOLVED")

    def test_radar_zone_entry_logged_as_high(self):
        entries = [{"id": "UNK-101", "x": 1, "y": 2, "range_km": 50.0, "bearing_deg": 10.0}]
        ids = services.log_radar_zone_entries(self.operator, entries)
        e = events.get_event(ids[0])
        self.assertEqual((e["domain"], e["severity"]), ("RADAR", "HIGH"))

    def test_injected_scenario_produces_one_three_domain_incident(self):
        res = services.inject_scenario(self.operator)
        self.assertEqual(len(res["event_ids"]), 4)       # RF + 2 cyber + radar
        evs = events.list_events()
        incidents = intel.correlate(evs, 10)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["domains"], ["CYBER", "RADAR", "RF"])
        self.assertGreaterEqual(intel.overall_score(evs), 50)

    def test_demo_history_covers_48_hours_all_domains_and_has_incidents(self):
        n = services.seed_demo_history()
        evs = events.list_events(limit=None)
        self.assertEqual(len(evs), n)
        self.assertEqual({e["domain"] for e in evs}, set(config.DOMAINS))
        oldest = min(e["ts"] for e in evs)
        self.assertGreater(utcnow() - __import__("defendx.timeutil", fromlist=["x"]).from_iso(oldest),
                           timedelta(hours=24))
        self.assertGreaterEqual(len(intel.correlate(evs, 10)), 4)
        self.assertGreaterEqual(len(intel.active_incidents(intel.correlate(evs, 10))), 1)

    def test_demo_history_is_reproducible_and_replaces_old_events(self):
        now = utcnow()
        services.seed_demo_history(now=now, seed=1)
        first = [(e["title"], e["ts"], e["status"]) for e in events.list_events(limit=None, newest_first=False)]
        services.seed_demo_history(now=now, seed=1)
        second = [(e["title"], e["ts"], e["status"]) for e in events.list_events(limit=None, newest_first=False)]
        self.assertEqual(first, second)

    def test_ensure_demo_data_is_idempotent(self):
        db_users = len(auth.list_users())
        services.ensure_demo_data()
        count = events.count_events()
        services.ensure_demo_data()
        self.assertEqual(events.count_events(), count)
        self.assertEqual(len(auth.list_users()), db_users)   # users already exist: no demo accounts added
        self.assertGreater(count, 0)                         # but the empty event store was seeded


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.events = [ev(1, "RF", 80, 0), ev(2, "CYBER", 70, 3), ev(3, "RADAR", 65, 5),
                       ev(4, "RF", 30, 200, "RESOLVED", "LOW")]
        self.report = intel.build_report(self.events, 10, "tester", now=T0)

    def test_report_numbers_match_the_engine(self):
        self.assertEqual(self.report["score"], intel.overall_score(self.events))
        self.assertEqual(self.report["level"], intel.risk_level(self.report["score"]))
        self.assertEqual(self.report["unresolved_events"], 3)
        self.assertEqual(self.report["total_events"], 4)
        self.assertEqual(len(self.report["incidents"]), len(intel.correlate(self.events, 10)))

    def test_markdown_contains_key_content(self):
        md = intel.render_markdown(self.report)
        for needle in (str(self.report["score"]), self.report["level"], "INC-001",
                       "event 1", "tester", "synthetic"):
            self.assertIn(needle, md)
        self.assertNotIn("event 4", md)                  # resolved: not in top unresolved list

    def test_html_contains_key_content_and_escapes(self):
        events_x = self.events + [dict(ev(9, "RF", 99, 400), title="<script>alert(1)</script>")]
        page = intel.render_html(intel.build_report(events_x, 10, "<b>me</b>", now=T0))
        self.assertTrue(page.startswith("<!DOCTYPE html>"))
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertNotIn("<b>me</b>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_empty_report_is_valid(self):
        r = intel.build_report([], 10, "x", now=T0)
        self.assertEqual((r["score"], r["level"]), (0.0, "LOW"))
        self.assertIn("No cross-domain incidents", intel.render_markdown(r))
        self.assertIn("No unresolved events", intel.render_html(r))

    def test_chart_helpers(self):
        m = intel.severity_matrix(self.events)
        self.assertEqual(int(m.loc["RF", "HIGH"]), 1)
        self.assertEqual(int(m.values.sum()), 3)         # resolved event excluded
        status = intel.domain_status(self.events)
        self.assertEqual(status["RF"]["status"], "ALERT")
        self.assertFalse(intel.events_per_hour([]).size)
        self.assertEqual(intel.events_per_hour(self.events)["count"].sum(), 4)
        self.assertEqual(len(intel.risk_trend(self.events)), 2)


if __name__ == "__main__":
    unittest.main()
