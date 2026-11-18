"""The 30-day chart cuts the sessions bars so one flood day cannot flatten the other days.
These tests run the real timelineModel() function from dashboard/index.html in node."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"
PLOT_HEIGHT = 138
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")

# The real 30 days from the live dashboard on 2026-11-18: (sessions, alerts) per day.
REAL_DAYS = [(9, 2), (11, 2), (14, 0), (4, 2), (6, 0), (17, 2), (11, 0), (19, 0), (7, 1), (27, 2),
             (11, 0), (8, 1), (17, 1), (28, 1), (14, 3), (8, 1), (16, 1), (9, 0), (14, 1), (21, 2),
             (11, 2), (17, 2), (21, 0), (91, 1), (17975, 0), (4, 0), (12, 1), (0, 2), (0, 0), (5, 1)]


def function_source(name):
    text = PAGE.read_text(encoding="utf-8")
    start = text.index(f"function {name}(")
    depth = 0
    for position in range(text.index("{", start), len(text)):
        if text[position] == "{":
            depth += 1
        elif text[position] == "}":
            depth -= 1
            if depth == 0:
                return text[start:position + 1]
    raise AssertionError(f"function {name} is not closed")


def run_model(days):
    payload = [{"day": f"d{i}", "honeypot": sessions, "other": alerts} for i, (sessions, alerts) in enumerate(days)]
    script = function_source("timelineModel") + f"\nprocess.stdout.write(JSON.stringify(timelineModel({json.dumps(payload)}, {PLOT_HEIGHT})));"
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def test_real_month_cuts_only_the_two_big_days():
    model = run_model(REAL_DAYS)
    assert model["cap"] == 55
    clipped_sessions = [sessions for (sessions, _), bar in zip(REAL_DAYS, model["bars"]) if bar["clipped"]]
    assert clipped_sessions == [91, 17975]


def test_every_alert_is_visible_on_the_real_month():
    model = run_model(REAL_DAYS)
    for (_, alerts), bar in zip(REAL_DAYS, model["bars"]):
        assert (bar["h2"] >= 2) if alerts else (bar["h2"] == 0)


def test_a_cut_bar_is_as_tall_as_the_cap_and_never_taller_than_the_plot():
    model = run_model(REAL_DAYS)
    for bar in model["bars"]:
        assert bar["h1"] + bar["h2"] <= PLOT_HEIGHT + 4        # +4: the 2 px minimum on both segments


def test_no_flood_day_means_nothing_is_cut():
    days = [(5, 0), (9, 1), (12, 0), (7, 2)] * 7
    model = run_model(days)
    assert not any(bar["clipped"] for bar in model["bars"])
    assert model["axisMax"] == max(sessions + alerts for sessions, alerts in days)


def test_empty_month_does_not_crash():
    model = run_model([])
    assert model["cap"] == 10 and model["bars"] == []


def test_quiet_days_are_zero_height_and_one_session_is_visible():
    model = run_model([(0, 0), (1, 0), (300, 0)])
    assert model["bars"][0]["h1"] == 0
    assert model["bars"][1]["h1"] >= 2


def test_two_flood_days_are_both_cut():
    days = [(10, 0)] * 28 + [(5000, 0), (9000, 0)]
    model = run_model(days)
    assert [bar["clipped"] for bar in model["bars"]][-2:] == [True, True]
    assert model["cap"] < 100


def test_many_big_days_are_not_outliers():
    """More than 10 percent of the month being huge is a new normal, not an outlier: nothing is cut."""
    days = [(10, 0)] * 26 + [(5000, 0), (6000, 0), (7000, 0), (8000, 0)]
    model = run_model(days)
    assert not any(bar["clipped"] for bar in model["bars"])


def test_selected_day_outline_is_not_the_alerts_colour():
    assert 'stroke:"#22d3ee"' not in function_source("timeline")
