import sys
import os
import subprocess
import json
import tempfile
import shutil
from pathlib import Path
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from collections import Counter
import logging
import warnings

# Suppress all DEBUG and INFO logs from libraries
logging.basicConfig(level=logging.WARNING)

# Suppress specific noisy loggers
logging.getLogger("androguard").setLevel(logging.ERROR)
logging.getLogger("androguard.core").setLevel(logging.ERROR)
logging.getLogger("androguard.core.axml").setLevel(logging.ERROR)
logging.getLogger("androguard.core.apk").setLevel(logging.ERROR)
logging.getLogger("Analyser").setLevel(logging.WARNING)
logging.getLogger("Analyser.Loader").setLevel(logging.WARNING)
logging.getLogger("Analyser.Engine").setLevel(logging.WARNING)
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

# Suppress warnings
warnings.filterwarnings("ignore")
# Add parent directory to path so Analyser can be imported
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

app = FastAPI(title="CyberKnights APK Analyzer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Use /tmp for temporary storage (writable in serverless)
UPLOAD_DIR = "/tmp/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def calculate_risk(findings):
    """Calculate risk score based on severity distribution"""
    severity_counts = Counter(f.get("severity", "Low") for f in findings)
    
    critical = severity_counts.get("Critical", 0)
    high = severity_counts.get("High", 0)
    medium = severity_counts.get("Medium", 0)
    low = severity_counts.get("Low", 0)
    
    raw_score = (critical * 15) + (high * 10) + (medium * 5) + (low * 2)
    risk_score = min(100, raw_score)
    
    if risk_score < 30:
        risk_level = "Safe"
    elif risk_score < 60:
        risk_level = "Moderate"
    else:
        risk_level = "High"
    
    summary = f"{critical} Critical, {high} High, {medium} Medium, {low} Low severity issues detected."
    
    return risk_score, risk_level, summary

@app.post("/analyze")
async def analyze_apk(file: UploadFile = File(...)):
    """Upload APK and run analysis"""
    if not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are allowed")
    
    # Save uploaded file to /tmp
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    try:
        # Create temp directory for outputs
        with tempfile.TemporaryDirectory() as output_dir:
            # Get the absolute path to analyse.py
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(current_dir)
            analyse_script = os.path.join(project_root, "Analyser", "analyse.py")
            
            # Run the analyzer CLI
            result = subprocess.run([
                sys.executable,
                analyse_script,
                file_path,
                "--format", "both",
                "--output", output_dir
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                print(f"STDERR: {result.stderr}")
                print(f"STDOUT: {result.stdout}")
                raise Exception(f"Analysis failed: {result.stderr}")
            
            # Find the generated files
            json_files = list(Path(output_dir).glob("*.json"))
            html_files = list(Path(output_dir).glob("*.html"))
            
            if not json_files:
                raise Exception("No report files generated")
            
            # Read the JSON report
            with open(json_files[0], 'r') as f:
                full_report = json.load(f)
            
            # Read HTML content if available
            html_content = None
            if html_files:
                with open(html_files[0], 'r') as f:
                    html_content = f.read()
            
            # Calculate risk score
            all_findings = full_report.get("all_findings", [])
            risk_score, risk_level, summary = calculate_risk(all_findings)
            
            # Extract permissions
            permissions = []
            for finding in all_findings:
                if finding.get("rule_id") == "DANGEROUS_PERMISSION_DECLARED":
                    perm = finding.get("evidence", {}).get("permission")
                    if perm:
                        permissions.append(perm)
            
            return {
                "success": True,
                "app_name": file.filename,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "summary": summary,
                "permissions": permissions[:15],
                "full_report": full_report,
                "html_report": html_content,
                "stats": {
                    "total_findings": full_report.get("analysis_summary", {}).get("total_findings", 0),
                    "critical": full_report.get("analysis_summary", {}).get("critical_findings", 0),
                    "high": full_report.get("analysis_summary", {}).get("high_findings", 0),
                    "medium": full_report.get("analysis_summary", {}).get("medium_findings", 0),
                    "low": full_report.get("analysis_summary", {}).get("low_findings", 0)
                }
            }
    
    except Exception as e:
        print(f"Error details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")
    
    finally:
        # Cleanup uploaded file
        if os.path.exists(file_path):
            os.unlink(file_path)

@app.get("/health")
async def health():
    return {"status": "healthy"}

# Mount static files - important: this should be the LAST route
app.mount("/", StaticFiles(directory="public", html=True), name="static")