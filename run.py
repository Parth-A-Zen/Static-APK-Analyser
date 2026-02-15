# run.py
import uvicorn
import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    print("=" * 60)
    print("🚀 CyberKnights APK Analyzer")
    print("=" * 60)
    print("📂 Starting server...")
    print("🌐 Open http://127.0.0.1:8000 in your browser")
    print(" Press Ctrl+C to stop")
    print("=" * 60)
    
    uvicorn.run(
        "api.index:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )