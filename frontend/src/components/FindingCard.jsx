const BADGES = {
  found_in_text: { text: "Found in the message", cls: "badge-evidence" },
  found_in_link: { text: "Found in the link", cls: "badge-evidence" },
  needs_verification: { text: "Needs verification", cls: "badge-assumption" },
};

export default function FindingCard({ finding }) {
  const badge = BADGES[finding.evidence_type] ?? BADGES.found_in_text;
  return (
    <article className="finding">
      <header>
        <h4>{finding.title}</h4>
        <span className="points">+{finding.points}</span>
      </header>
      <span className={`badge ${badge.cls}`}>{badge.text}</span>
      <p className="why">{finding.why}</p>
      {finding.evidence.length > 0 && (
        <ul className="evidence">
          {finding.evidence.map((e, i) => (
            <li key={i}>{e}</li>
          ))}
        </ul>
      )}
    </article>
  );
}
