import os
import shutil
from collections import Counter
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Import your analyzer function
from Analyser.analyse import run_analysis


app = FastAPI(title="CyberKnights APK Analyzer API")

# Enable CORS for hackathon demo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow frontend connection
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


def calculate_risk(findings):
    """
    Calculate risk score and level based on severity distribution
    """
    severity_counts = Counter(f.get("severity", "Low") for f in findings)

    high = severity_counts.get("High", 0)
    medium = severity_counts.get("Medium", 0)
    low = severity_counts.get("Low", 0)

    # Weighted risk formula
    raw_score = (high * 10) + (medium * 5) + (low * 2)
    risk_score = min(100, raw_score)

    if risk_score < 40:
        risk_level = "Safe"
    elif risk_score < 75:
        risk_level = "Moderate"
    else:
        risk_level = "High"

    summary = f"{high} High, {medium} Medium, {low} Low severity issues detected."

    return risk_score, risk_level, summary


@app.post("/analyze")
async def analyze_apk(file: UploadFile = File(...)):
    # Validate file type
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are allowed")

    file_path = os.path.join(UPLOAD_DIR, file.filename)

    # Save uploaded file
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File save failed: {str(e)}")

    # Run analysis
    try:
        report = run_analysis(file_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

    # Extract data safely
    findings = report.get("findings", [])
    permissions = report.get("permissions", [])
    app_name = report.get("app_name", file.filename)

    risk_score, risk_level, summary = calculate_risk(findings)

    # Prepare frontend-friendly response
    response = {
        "app_name": app_name,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "permissions": permissions,
        "summary": summary,
        "findings": findings
    }

    return response
