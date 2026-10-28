const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

export default function ScoreGauge({ score, level, label }) {
  const offset = CIRCUMFERENCE * (1 - score / 100);
  return (
    <div className={`gauge level-${level}`} role="img" aria-label={`Risk indicator score ${score} out of 100, ${label}`}>
      <svg viewBox="0 0 120 120" width="150" height="150">
        <circle className="gauge-track" cx="60" cy="60" r={RADIUS} />
        <circle
          className="gauge-value"
          cx="60"
          cy="60"
          r={RADIUS}
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
          transform="rotate(-90 60 60)"
        />
      </svg>
      <div className="gauge-text">
        <span className="gauge-score">{score}</span>
        <span className="gauge-max">/100</span>
      </div>
    </div>
  );
}
