# PhishShield

Explainable AI phishing-message and URL analysis student prototype.

## Requirements
- Python 3.10+
- Node.js 20+
- npm

## 1. Backend setup (Windows PowerShell or CMD)

```bash
cd backend
python -m venv myenv
myenv\Scripts\activate
pip install -r requirements.txt
python train_model.py
python app.py
```

The API runs at http://127.0.0.1:5000.

## 2. Frontend setup (open a second terminal)

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL printed in the terminal, normally http://localhost:5173.

## API
- `GET /api/health`
- `POST /api/scan` with JSON `{"message":"..."}`
- `GET /api/history`

## Important limitations
- `backend/data/messages.csv` is a tiny demonstration dataset, not a research-grade dataset.
- Replace it with a larger, legally obtained, carefully labelled phishing/legitimate dataset.
- The URL checks are heuristics. The app does not visit URLs or verify a live website.
- Risk score is a heuristic index, not a calibrated probability.
- Category detection is keyword-based.
- Do not submit real passwords, OTPs, private email content or sensitive personal information.
- This prototype is not a production security product and cannot guarantee safety.
- Do not expose the history API publicly without authentication and access controls.
- For deployment, use a production WSGI server, HTTPS, environment-based configuration, rate limiting and security review.
