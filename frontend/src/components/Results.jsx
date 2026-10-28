import ScoreGauge from "./ScoreGauge.jsx";
import HighlightedText from "./HighlightedText.jsx";
import FindingCard from "./FindingCard.jsx";
import UrlPanel from "./UrlPanel.jsx";

export default function Results({ result, analyzedText }) {
  return (
    <div className="results" aria-live="polite">
      <section className={`card summary level-${result.level}`}>
        <ScoreGauge score={result.score} level={result.level} label={result.level_label} />
        <div className="summary-text">
          <span className="level-pill">{result.level_label}</span>
          <p>{result.summary}</p>
          <p className="muted small">{result.score_note}</p>
        </div>
      </section>

      {result.notes.map((n, i) => (
        <p key={i} className="notice">{n}</p>
      ))}

      {analyzedText.trim() && result.highlights.length > 0 && (
        <section className="card">
          <h3>Where the warning signs are</h3>
          <p className="muted small">Hover or focus a highlight to see what it triggered.</p>
          <HighlightedText text={analyzedText} highlights={result.highlights} />
        </section>
      )}

      <section className="card">
        <h3>Why this score</h3>
        {result.findings.length === 0 ? (
          <p>No known warning signs were found in this content.</p>
        ) : (
          <div className="findings">
            {result.findings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </div>
        )}
        <p className="muted small legend">
          <span className="badge badge-evidence">Found in…</span> means we can point to it in what you
          submitted. <span className="badge badge-assumption">Needs verification</span> is something we
          cannot confirm and you should check yourself.
        </p>
      </section>

      <UrlPanel urls={result.urls} />

      <section className="card">
        <h3>What to do next</h3>
        <ul className="steps">
          {result.next_steps.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ul>
        <h4>Verification checklist</h4>
        <ul className="checklist">
          {result.verification_checklist.map((s, i) => (
            <li key={i}>
              <label>
                <input type="checkbox" /> {s}
              </label>
            </li>
          ))}
        </ul>
      </section>

      {result.report_guidance && (
        <section className="card report">
          <h3>{result.report_guidance.title}</h3>
          <ul className="steps">
            {result.report_guidance.items.map((s, i) => (
              <li key={i}>{s}</li>
            ))}
          </ul>
          <p className="muted small">{result.report_guidance.note}</p>
        </section>
      )}

      <p className="disclaimer">{result.disclaimer}</p>
    </div>
  );
}
