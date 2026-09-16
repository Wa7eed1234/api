# Text similarity API

Flask REST API with /register, /detect and /refill. Registration grants six tokens; text comparison uses spaCy and consumes one token.

## Run locally

Use Python 3 in an isolated environment. The following dependency list is inferred from source imports; this repository has no tested dependency lockfile.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install Flask Flask-RESTful Flask-SQLAlchemy bcrypt spacy
python -m spacy download en_core_web_sm
python -m flask --app main run --host 127.0.0.1 --port 5000
```

Open http://127.0.0.1:5000 (the API exposes POST endpoints rather than a home page). Use only synthetic local records. Complete the known repairs below first; dependency compatibility and full application flows have not been verified.

## Current status and known limitations

Remove request logging of passwords; replace the hardcoded refill password with proper authorization. Refill currently sets the token balance rather than adding to it. The small spaCy model has limited similarity quality.

## Review status

Documentation drafted from repository source on 13 September 2026. This review did not run the application or certify it for production.
