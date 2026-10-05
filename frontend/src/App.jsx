import { useState } from "react";
import {
  AlertCircle,
  ArrowUpRight,
  CheckCircle2,
  Globe2,
  KeyRound,
  LoaderCircle,
  Radar,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import "./App.css";

const API_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [feedbackUrl, setFeedbackUrl] = useState("");
  const [feedbackLabel, setFeedbackLabel] = useState(0);
  const [adminKey, setAdminKey] = useState("");
  const [feedbackMessage, setFeedbackMessage] = useState("");
  const [feedbackError, setFeedbackError] = useState("");
  const [isSubmittingFeedback, setIsSubmittingFeedback] = useState(false);

  async function scanUrl(event) {
    event.preventDefault();
    const normalizedUrl = url.trim();

    if (!normalizedUrl) {
      setError("Enter a URL before scanning.");
      setResult(null);
      return;
    }

    setIsLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalizedUrl }),
      });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          data.detail || "The scanner could not process that URL.",
        );
      }

      setResult(data);
    } catch (scanError) {
      setError(
        scanError instanceof TypeError
          ? "The scanner is offline. Start the FastAPI backend and try again."
          : scanError.message,
      );
    } finally {
      setIsLoading(false);
    }
  }

  const isPhishing = result?.label === "phishing";

  async function submitFeedback(event) {
    event.preventDefault();
    const normalizedUrl = feedbackUrl.trim();

    if (!normalizedUrl || !adminKey.trim()) {
      setFeedbackError("Enter the URL and admin key before submitting.");
      setFeedbackMessage("");
      return;
    }

    setIsSubmittingFeedback(true);
    setFeedbackError("");
    setFeedbackMessage("");

    try {
      const response = await fetch(`${API_URL}/feedback`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Admin-Key": adminKey.trim(),
        },
        body: JSON.stringify({ url: normalizedUrl, label: feedbackLabel }),
      });
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.detail || "Feedback could not be submitted.");
      }

      setFeedbackMessage("Feedback saved. The model has been retrained.");
      setFeedbackUrl("");
    } catch (feedbackSubmitError) {
      setFeedbackError(
        feedbackSubmitError instanceof TypeError
          ? "The backend is offline. Start FastAPI and try again."
          : feedbackSubmitError.message,
      );
    } finally {
      setIsSubmittingFeedback(false);
    }
  }

  return (
    <main className="app-shell">
      <section className="hero-grid">
        <div className="hero-copy">
          <p className="eyebrow">
            <Sparkles size={15} /> Adaptive URL intelligence
          </p>
          <h1>Know what’s behind the link.</h1>
          <p className="hero-lede">
            Check a URL before you click. We study its structure and flags
            suspicious patterns in seconds.
          </p>

          <form className="scan-form" onSubmit={scanUrl}>
            <div className="input-wrap">
              <Globe2 size={20} aria-hidden="true" />
              <input
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="Paste a URL to inspect"
                aria-label="URL to inspect"
                maxLength={2048}
                type="url"
              />
            </div>
            <button className="scan-button" type="submit" disabled={isLoading}>
              {isLoading ? (
                <LoaderCircle className="spin" size={18} />
              ) : (
                <ShieldCheck size={18} />
              )}
              {isLoading ? "Checking..." : "Scan URL"}
              {!isLoading && <ArrowUpRight size={17} />}
            </button>
          </form>

          {error && (
            <div className="message error-message" role="alert">
              <AlertCircle size={18} /> {error}
            </div>
          )}

          <div className="trust-row">
            <span>
              <CheckCircle2 size={16} /> Bounded page check
            </span>
            <span>
              <CheckCircle2 size={16} /> Fast feature scan
            </span>
            <span>
              <CheckCircle2 size={16} /> Private input
            </span>
          </div>
        </div>

        <div
          className={`result-panel ${result ? (isPhishing ? "danger" : "safe") : "empty"}`}
          aria-live="polite"
        >
          {!result ? (
            <div className="empty-state">
              <div className="radar-orbit">
                <Radar size={36} />
              </div>
              <p className="result-kicker">Awaiting a URL</p>
              <h2>Your scan will appear here.</h2>
              <p>
                Paste a link on the left to see the model’s assessment and
                confidence.
              </p>
            </div>
          ) : (
            <div className="result-state">
              <div className="result-icon">
                {isPhishing ? (
                  <AlertCircle size={34} />
                ) : (
                  <CheckCircle2 size={34} />
                )}
              </div>
              <p className="result-kicker">Scan complete</p>
              <h2>{isPhishing ? "Potential phishing" : "Looks legitimate"}</h2>
              <p className="result-url">{url}</p>
              <div className="confidence-row">
                <span>Model confidence</span>
                <strong>{Math.round((result.confidence || 0) * 100)}%</strong>
              </div>
              <div className="confidence-track">
                <span style={{ width: `${(result.confidence || 0) * 100}%` }} />
              </div>
              <p className="result-note">
                {isPhishing
                  ? "Avoid entering credentials or payment details on this site."
                  : "Still verify the sender and context before sharing sensitive information."}
              </p>
              {result.risk_signals?.length > 0 && (
                <div className="risk-signals">
                  <strong>Signals detected</strong>
                  <ul>
                    {result.risk_signals.map((signal) => (
                      <li key={signal}>{signal}</li>
                    ))}
                  </ul>
                </div>
              )}
              {result.web_checks && (
                <div className="web-checks">
                  <strong>Website checks</strong>
                  <div className="web-check-grid">
                    <span>
                      Reachable{" "}
                      <b>{result.web_checks.reachable ? "Yes" : "No"}</b>
                    </span>
                    <span>
                      DNS{" "}
                      <b>
                        {result.web_checks.dns?.resolved
                          ? "Resolved"
                          : "Failed"}
                      </b>
                    </span>
                    <span>
                      Redirects{" "}
                      <b>{result.web_checks.redirects?.length || 0}</b>
                    </span>
                    <span>
                      Password forms{" "}
                      <b>{result.web_checks.password_forms || 0}</b>
                    </span>
                  </div>
                  {result.web_checks.title && (
                    <p className="page-title">
                      Page title: {result.web_checks.title}
                    </p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </section>

      <section className="feature-strip">
        <div>
          <span className="feature-number">01</span>
          <div>
            <h3>Structure first</h3>
            <p>Reads URL without visiting the destination.</p>
          </div>
        </div>
        <div>
          <span className="feature-number">02</span>
          <div>
            <h3>Model-backed</h3>
            <p>Classifies patterns learned from labeled URL data.</p>
          </div>
        </div>
        <div>
          <span className="feature-number">03</span>
          <div>
            <h3>Always improving</h3>
            <p>Verified feedback can help refresh the model over time.</p>
          </div>
        </div>
      </section>
      <section className="feedback-section">
        <div className="feedback-heading">
          <p className="eyebrow">
            <KeyRound size={15} /> Admin model feedback
          </p>
          <h2>Teach the scanner one verified URL at a time.</h2>
          <p>
            Use this panel only when you know the correct label. Each submission
            retrains the model.
          </p>
        </div>
        <form className="feedback-form" onSubmit={submitFeedback}>
          <label>
            Verified URL
            <input
              value={feedbackUrl}
              onChange={(event) => setFeedbackUrl(event.target.value)}
              placeholder="https://verified-site.com"
              maxLength={2048}
              type="url"
            />
          </label>
          <label>
            Admin key
            <input
              value={adminKey}
              onChange={(event) => setAdminKey(event.target.value)}
              placeholder="From your .env file"
              type="password"
              autoComplete="off"
            />
          </label>
          <div
            className="feedback-labels"
            role="group"
            aria-label="Verified URL label"
          >
            <button
              type="button"
              className={feedbackLabel === 0 ? "selected danger-choice" : ""}
              onClick={() => setFeedbackLabel(0)}
            >
              Phishing
            </button>
            <button
              type="button"
              className={feedbackLabel === 1 ? "selected safe-choice" : ""}
              onClick={() => setFeedbackLabel(1)}
            >
              Legitimate
            </button>
          </div>
          <button
            className="feedback-submit"
            type="submit"
            disabled={isSubmittingFeedback}
          >
            {isSubmittingFeedback ? (
              <LoaderCircle className="spin" size={17} />
            ) : (
              <KeyRound size={17} />
            )}
            {isSubmittingFeedback
              ? "Retraining..."
              : "Submit verified feedback"}
          </button>
          {feedbackError && (
            <div className="message error-message" role="alert">
              <AlertCircle size={18} /> {feedbackError}
            </div>
          )}
          {feedbackMessage && (
            <div className="message success-message" role="status">
              <CheckCircle2 size={18} /> {feedbackMessage}
            </div>
          )}
        </form>
      </section>
    </main>
  );
}

export default App;
