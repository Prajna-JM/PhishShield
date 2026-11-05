import React from 'react';
import { useEffect, useState } from 'react';
import axios from 'axios';

const API = 'http://127.0.0.1:5000/api';

function App() {
  const [message, setMessage] = useState('');
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function loadHistory() {
    try {
      const response = await axios.get(`${API}/history`);
      setHistory(response.data);
    } catch {
      // History is optional; the scan result remains usable.
    }
  }

  useEffect(() => { loadHistory(); }, []);

  async function scanMessage(event) {
    event.preventDefault();
    if (!message.trim()) {
      setError('Paste a message before scanning.');
      return;
    }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const response = await axios.post(`${API}/scan`, { message });
      setResult(response.data);
      await loadHistory();
    } catch (err) {
      setError(err.response?.data?.error || 'Cannot reach the API. Check that Flask is running.');
    } finally {
      setLoading(false);
    }
  }

  const riskClass = result?.risk_level?.toLowerCase() || '';

  return (
    <div className="page">
      <header className="topbar">
        <a className="brand" href="#"><span className="shield">✦</span> PhishShield</a>
        <span className="top-note">Explainable AI · Message & URL security</span>
      </header>

      <main className="main">
        <section className="intro">
          <div className="eyebrow">AI-POWERED CYBER SAFETY</div>
          <h1>Spot the scam.<br /><span>Understand the risk.</span></h1>
          <p>Analyze suspicious SMS messages and emails. Get a prediction, URL checks and clear warning signs.</p>
        </section>

        <section className="panel scanner">
          <div className="section-title">
            <div><div className="eyebrow">NEW ANALYSIS</div><h2>Message scanner</h2></div>
            <span className="live"><i /> Local model</span>
          </div>
          <form onSubmit={scanMessage}>
            <label htmlFor="message">Paste the message or email text</label>
            <textarea
              id="message"
              value={message}
              onChange={e => setMessage(e.target.value)}
              maxLength={10000}
              placeholder="Example: Your account will be blocked. Verify your details immediately..."
            />
            <div className="form-footer">
              <span>{message.length.toLocaleString()} / 10,000 characters</span>
              <button disabled={loading}>{loading ? 'Analyzing…' : 'Analyze message  →'}</button>
            </div>
          </form>
          {error && <div className="error" role="alert">{error}</div>}
          <p className="privacy-note">Your text is analyzed by your local backend. Avoid entering real passwords, OTPs or private information.</p>
        </section>

        {result && (
          <section className="panel report" aria-live="polite">
            <div className="section-title">
              <div><div className="eyebrow">SCAN RESULT</div><h2>Security report</h2></div>
              <span className={`pill ${riskClass}`}>{result.risk_level} risk</span>
            </div>
            <div className="score-row">
              <div>
                <div className="prediction">{result.prediction}</div>
                <p className="muted">Category: {result.category}</p>
                <p className="muted">Text model phishing score: {result.text_model_probability}%</p>
              </div>
              <div className={`score ${riskClass}`}><strong>{result.risk_score}</strong><span>/ 100</span></div>
            </div>
            <div className="meter"><div className={riskClass} style={{ width: `${result.risk_score}%` }} /></div>

            <div className="report-grid">
              <div className="subpanel">
                <h3>Why it was flagged</h3>
                {result.warning_signs.length
                  ? <ul>{result.warning_signs.map((item, i) => <li key={i}>{item}</li>)}</ul>
                  : <p className="muted">No rule-based warning signs were found.</p>}
              </div>
              <div className="subpanel">
                <h3>Model explanation</h3>
                {result.model_explanations.length
                  ? <ul>{result.model_explanations.map((item, i) => <li key={i}><code>{item.term}</code> <span className="muted">({item.contribution})</span></li>)}</ul>
                  : <p className="muted">No strong positive feature contributions.</p>}
              </div>
            </div>

            <div className="subpanel url-panel">
              <h3>URL analysis</h3>
              {result.urls.length
                ? result.urls.map((item, i) => (
                  <div className="url-result" key={i}>
                    <strong>{item.domain || 'Unparsed URL'}</strong>
                    <span className="url-score">Heuristic score: {item.score}/100</span>
                    {item.reasons.length ? <ul>{item.reasons.map((reason, j) => <li key={j}>{reason}</li>)}</ul> : <p className="muted">No URL warning rules triggered.</p>}
                  </div>
                ))
                : <p className="muted">No URLs found in this message.</p>}
            </div>
            <div className="recommendation"><strong>Recommended action</strong><p>{result.recommendation}</p></div>
            <p className="disclaimer">This is a student prototype, not a security guarantee. A low score does not prove a message is safe.</p>
          </section>
        )}

        <section className="panel history">
          <div className="section-title">
            <div><div className="eyebrow">LOCAL DATABASE</div><h2>Recent scans</h2></div>
            <button className="secondary" onClick={loadHistory}>Refresh</button>
          </div>
          {history.length === 0 ? <p className="muted">No scans yet. Your recent analyses will appear here.</p> :
            <div className="table-wrap"><table>
              <thead><tr><th>Message preview</th><th>Result</th><th>Risk</th><th>Category</th></tr></thead>
              <tbody>{history.map(row => (
                <tr key={row.id}>
                  <td className="preview">{row.message_preview}</td>
                  <td>{row.prediction}</td>
                  <td>{row.risk_score}/100</td>
                  <td>{row.category}</td>
                </tr>
              ))}</tbody>
            </table></div>}
        </section>
        <footer>PhishShield · Educational prototype · Do not use as the sole basis for security decisions.</footer>
      </main>
    </div>
  );
}

export default App;
