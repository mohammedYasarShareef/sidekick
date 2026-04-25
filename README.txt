

━━━ FOR END USERS (receiving only Sidekick.exe) ━━━━━━━━━━━

  • Just double-click Sidekick.exe
  • Windows will ask for Administrator access — click YES
  • The app starts automatically. No installation needed.
  • These files are created automatically in the same folder:
      sidekick.key          → Encryption key (do NOT delete)
      sidekick_logs.enc     → Encrypted event log
      sidekick_sessions.json → Session history
      sidekick_state.json   → Process hash database

━━━ FOR DEVELOPERS (building from source) ━━━━━━━━━━━━━━━━━

  Requirements:
    • Python 3.10 or higher
    • Windows 10/11 (64-bit)

  Build steps:
    1. Double-click BUILD_WINDOWS.bat
       (or run it from a Command Prompt)
    2. Wait for the build to complete (~1-2 minutes)
    3. Find your executable at:  dist\Sidekick.exe

━━━ WHAT SIDEKICK MONITORS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Automatically detects and watches:
    Ollama, LM Studio, LocalAI, Jan, KoboldCPP,
    Python-based AI servers (Gradio, Streamlit, FastAPI),
    Uvicorn, vLLM, TabbyML, ComfyUI, and more.

  For each agent it tracks:
    ✓ Start time & duration
    ✓ Safety Score (0-100): starts at 100, deducts for anomalies
    ✓ Software Attestation (SHA-256 hash verification)
    ✓ Network monitoring (auto-kills on unauthorized outbound)
    ✓ I/O spike detection (auto-kills on mass data read/write)
    ✓ Encrypted session log with full history

  Safety Score breakdown:
    85-100  SAFE        Normal operation
    60-84   LOW RISK    Minor anomalies observed
    35-59   SUSPICIOUS  Significant deductions
    15-34   DANGEROUS   Major anomalies
    0-14    CRITICAL    Imminent threat

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
