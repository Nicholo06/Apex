from fastapi import FastAPI, UploadFile, File, HTTPException
from backend.core.scanner import APKScanner
from backend.core.dynamic import FridaOrchestrator
from backend.ai.provider import AIProviderFactory
from backend.config import config
import os
import shutil

from backend.core.dumper import ADBDumper

app = FastAPI(title="APex: AI-Powered APK Explorer")

@app.get("/")
async def root():
    return {
        "message": "APex Backend is running!",
        "documentation": "/docs",
        "status": "healthy"
    }

@app.post("/exfiltrate/{package_name}")
async def exfiltrate_data(package_name: str):
    dumper = ADBDumper(package_name)
    results = dumper.pull_data()
    return {"status": "success", "results": results}

@app.post("/scan")
async def scan_apk(file: UploadFile = File(...)):
    try:
        # Sanitize filename (remove spaces)
        safe_filename = file.filename.replace(" ", "_")
        apk_path = os.path.join("temp_decompiled", safe_filename)
        
        # Ensure directory exists
        if not os.path.exists("temp_decompiled"):
            os.makedirs("temp_decompiled")
            
        with open(apk_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        scanner = APKScanner(apk_path)
        if scanner.decompile():
            findings = scanner.find_security_logic()
            return {"status": "success", "findings": findings}
        else:
            raise HTTPException(status_code=500, detail="Decompilation failed. Check if Java is installed and pyapktool is working.")
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scripts")
async def list_scripts():
    orchestrator = FridaOrchestrator(None)
    return {"scripts": orchestrator.list_scripts()}

@app.post("/inject/{package_name}/{script_name}")
async def inject_script(package_name: str, script_name: str):
    orchestrator = FridaOrchestrator(package_name)
    if orchestrator.attach_and_inject(script_name):
        return {"status": "success", "message": f"Injected {script_name} into {package_name}"}
    else:
        raise HTTPException(status_code=500, detail="Injection failed")

@app.post("/ai-generate-hook")
async def ai_generate_hook(smali_code: str, category: str):
    try:
        provider = AIProviderFactory.get_provider()
        hook_code = provider.generate_hook(smali_code, category)
        
        # Save to frida-scripts/ai_generated.js
        hook_path = os.path.join(config.FRIDA_SCRIPTS_PATH, "ai_generated.js")
        with open(hook_path, "w") as f:
            f.write(hook_code)
            
        return {"status": "success", "hook": hook_code, "file": "ai_generated.js"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
