// Offsets from the API are UTF-16 code units, which is exactly what JS string.slice uses.
export default function HighlightedText({ text, highlights }) {
  const parts = [];
  let pos = 0;
  highlights.forEach((h, i) => {
    if (h.start > pos) parts.push(text.slice(pos, h.start));
    parts.push(
      <mark key={i} title={h.labels.join(" · ")} tabIndex={0}>
        {text.slice(h.start, h.end)}
      </mark>
    );
    pos = h.end;
  });
  if (pos < text.length) parts.push(text.slice(pos));
  return <p className="highlighted">{parts}</p>;
}
