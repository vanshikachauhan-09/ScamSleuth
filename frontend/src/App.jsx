import { useEffect, useRef, useState } from "react";
import { analyze, getSamples } from "./api.js";
import Results from "./components/Results.jsx";

const MAX_TEXT = 5000;

export default function App() {
  const [text, setText] = useState("");
  const [url, setUrl] = useState("");
  const [samples, setSamples] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [analyzedText, setAnalyzedText] = useState("");
  const resultsRef = useRef(null);

  useEffect(() => {
    getSamples().then(setSamples).catch(() => setSamples([]));
  }, []);

  async function run(nextText = text, nextUrl = url) {
    setError("");
    if (!nextText.trim() && !nextUrl.trim()) {
      setError("Paste a message or a link to analyze.");
      return;
    }
    setLoading(true);
    try {
      const data = await analyze({ text: nextText, url: nextUrl });
      setResult(data);
      setAnalyzedText(nextText);
      requestAnimationFrame(() =>
        resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" })
      );
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  function loadSample(sample) {
    setText(sample.text);
    setUrl(sample.url);
    run(sample.text, sample.url);
  }

  function clearAll() {
    setText("");
    setUrl("");
    setResult(null);
    setError("");
  }

  return (
    <div className="page">
      <header className="hero">
        <h1>
          Scam<span>Sleuth</span>
        </h1>
        <p>
          Paste a suspicious message, job offer, scholarship notice or link. We don't just say
          "safe" or "dangerous". We show you the hidden warning signs and what to do next.
        </p>
      </header>

      <main>
        <section className="card input-card">
          <label htmlFor="msg">Message, offer or notice</label>
          <textarea
            id="msg"
            rows={8}
            maxLength={MAX_TEXT}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste the full message here…"
          />
          <div className="counter muted small">
            {text.length}/{MAX_TEXT}
          </div>

          <label htmlFor="url">Link (optional)</label>
          <input
            id="url"
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://…  (we only inspect the text of the link, we never open it)"
            maxLength={2048}
          />

          <div className="actions">
            <button className="primary" onClick={() => run()} disabled={loading}>
              {loading ? "Analyzing…" : "Analyze"}
            </button>
            <button className="ghost" onClick={clearAll} disabled={loading}>
              Clear
            </button>
          </div>

          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}

          {samples.length > 0 && (
            <div className="samples">
              <span className="muted small">Try an example:</span>
              <div className="chips">
                {samples.map((s) => (
                  <button
                    key={s.id}
                    className={`chip ${s.kind}`}
                    onClick={() => loadSample(s)}
                    title={s.kind === "scam" ? "Example scam" : "Example legitimate message"}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          <p className="privacy muted small">
            Privacy: your text is analyzed in memory and is not stored. Avoid pasting passwords or full
            card numbers.
          </p>
        </section>

        <div ref={resultsRef}>
          {result && <Results result={result} analyzedText={analyzedText} />}
        </div>
      </main>

      <footer>
        ScamSleuth highlights warning signs; it cannot guarantee that a message is a scam or is safe.
      </footer>
    </div>
  );
}
