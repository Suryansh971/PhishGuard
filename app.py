from flask import Flask, render_template, request
from analyzer import analyze_url, calculate_final_score
from threat_api import scan_url, wait_for_analysis, get_stats
from database import (
    init_db,
    save_scan,
    get_scan_history,
    get_dashboard_stats
)

app = Flask(__name__)
init_db()

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form["url"]

    local_result = analyze_url(url)

    try:
        scan_result = scan_url(url)
        analysis_id = scan_result["data"]["id"]

        analysis_result = wait_for_analysis(analysis_id)
        vt_stats = get_stats(analysis_result)

    except Exception as e:
        print("VirusTotal Error:", e)

        vt_stats = {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0
        }

    final_score, final_risk = calculate_final_score(
        local_result["score"],
        vt_stats
    )
    save_scan(
        url,
        final_score,
        final_risk,
        vt_stats
    )

    return render_template(
        "result.html",
        url=url,
        result=local_result,
        vt_stats=vt_stats,
        final_score=final_score,
        final_risk=final_risk
    )

@app.route("/history")
def history():
    scans = get_scan_history()

    return render_template(
        "history.html",
        scans=scans
    )

@app.route("/dashboard")
def dashboard():
    stats = get_dashboard_stats()

    return render_template(
        "dashboard.html",
        stats=stats
    )

if __name__ == "__main__":
    app.run(debug=True)