export default function UrlPanel({ urls }) {
  if (!urls.length) return null;
  return (
    <section className="card">
      <h3>Links checked</h3>
      <p className="muted small">
        We only read the text of each link. We never open it, so nothing was visited on your behalf.
      </p>
      <ul className="urls">
        {urls.map((u, i) => (
          <li key={i}>
            <code>{u.url}</code>
            {!u.valid ? (
              <p className="muted small">Could not be parsed as a link.</p>
            ) : u.flags.length === 0 ? (
              <p className="muted small">No structural red flags in the link text.</p>
            ) : (
              <ul className="flags">
                {u.flags.map((f, j) => (
                  <li key={j} className={`sev-${f.severity}`}>
                    <span className="sev">{f.severity}</span> {f.detail}
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
