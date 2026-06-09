# Risk score thresholds
RISK_SAFE_MAX = 39
RISK_SUSPICIOUS_MAX = 79
RISK_CRITICAL_MIN = 80

# UEBA rule-based thresholds (fallback when < 3 developers in DB)
UEBA_AVG_RISK_THRESHOLD = 50
UEBA_MAX_RISK_THRESHOLD = 80

# Analysis limits
MAX_DIFF_CHARS_PER_COMMIT = 3000   # chars per commit in batch prompt
MAX_DIFF_TOTAL_CHARS = 50_000      # hard cap before binary-file warning
MAX_BATCH_SIZE = 20                # max commits sent in a single AI request
TOP_RISKY_DEVS = 5                 # how many developers shown in dashboard chart

# Git
CLONE_BASE_DIR = "data/clones"
COMMIT_FETCH_COUNT = 20
