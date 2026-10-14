import { useEffect, useState } from "react";
import { api } from "../api";
import { S, card, btn } from "../types";

const TIPS = [
  { icon: "🎣", title: "Phishing Signs", text: "Look for urgency cues, look-alike domains, unexpected attachments, and requests for passwords or personal data." },
  { icon: "🔑", title: "Strong Credentials", text: "Use unique, long passphrases (4+ random words), a password manager, and multi-factor authentication on every account." },
  { icon: "🔗", title: "Safe Browsing", text: "Type official addresses yourself instead of clicking unexpected links. Hover over links to preview the real destination." },
];

export default function Quiz() {
  const [questions, setQuestions] = useState<S[]>([]);
  const [answers, setAnswers] = useState<number[]>([]);
  const [result, setResult] = useState<S>();
  const [err, setErr] = useState("");
  const [history, setHistory] = useState<S[]>([]);
  const [submitting, setSubmitting] = useState(false);

  const load = () => {
    api("/awareness/quiz").then((x) => {
      setQuestions(x.questions);
      setAnswers(x.questions.map(() => -1));
      setResult(undefined);
    }).catch((x) => setErr(x.message));
    api("/awareness/attempts").then(setHistory).catch(() => {});
  };

  useEffect(load, []);

  async function handleSubmit() {
    setSubmitting(true);
    try {
      const res = await api("/awareness/quiz/submit", {
        method: "POST",
        body: JSON.stringify({ answers }),
      });
      setResult(res);
      api("/awareness/attempts").then(setHistory).catch(() => {});
    } catch (x: any) {
      setErr(x.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-5">
      {/* Tips section */}
      <div className={`${card}`}>
        <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-slate-400">
          🛡 Awareness Tips
        </h3>
        <div className="grid gap-3 sm:grid-cols-3">
          {TIPS.map((t) => (
            <div key={t.title} className="rounded-lg bg-[#0a1628] p-3 border border-cyan-900/20">
              <p className="mb-1 text-lg">{t.icon}</p>
              <p className="text-sm font-semibold text-slate-200">{t.title}</p>
              <p className="mt-1 text-xs text-slate-400 leading-relaxed">{t.text}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Error */}
      {err && (
        <p className="rounded-lg bg-red-500/10 border border-red-500/20 p-3 text-sm text-red-300">{err}</p>
      )}

      {/* Questions */}
      {questions.map((q, i) => (
        <div key={q.id} className={card}>
          <p className="mb-3 font-semibold text-slate-100">
            <span className="mr-2 inline-flex h-6 w-6 items-center justify-center rounded-full bg-cyan-500/20 text-xs text-cyan-300">{i + 1}</span>
            {q.question}
          </p>
          <div className="space-y-2">
            {q.options.map((o: string, j: number) => (
              <label
                key={j}
                className={`flex cursor-pointer items-center gap-3 rounded-lg border px-3 py-2 text-sm transition-all duration-150 ${
                  result
                    ? j === q.correct_index
                      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
                      : answers[i] === j && j !== q.correct_index
                      ? "border-red-500/40 bg-red-500/10 text-red-200"
                      : "border-slate-700 text-slate-400"
                    : answers[i] === j
                    ? "border-cyan-500/50 bg-cyan-500/10 text-cyan-200"
                    : "border-slate-700 text-slate-400 hover:border-slate-600 hover:bg-slate-800/40"
                }`}
              >
                <input
                  type="radio"
                  name={`q${i}`}
                  disabled={!!result}
                  checked={answers[i] === j}
                  onChange={() => setAnswers(answers.map((x, k) => (k === i ? j : x)))}
                  className="accent-cyan-400"
                />
                {o}
              </label>
            ))}
          </div>
          {result && (
            <p className={`mt-3 flex items-start gap-2 text-sm ${result.results[i].correct ? "text-emerald-300" : "text-red-300"}`}>
              <span>{result.results[i].correct ? "✅" : "❌"}</span>
              <span>
                <b>{result.results[i].correct ? "Correct. " : "Incorrect. "}</b>
                {result.results[i].explanation}
              </span>
            </p>
          )}
        </div>
      ))}

      {/* Submit / Score */}
      {questions.length > 0 && (
        result ? (
          <div className={`${card} flex items-center justify-between flex-wrap gap-3`}>
            <div>
              <p className="text-sm text-slate-400">Your score</p>
              <p className="text-3xl font-bold text-cyan-300">
                {result.score}<span className="text-lg text-slate-400">/{result.total}</span>
              </p>
            </div>
            <button
              className={btn}
              onClick={() => { setResult(undefined); load(); }}
            >
              🔁 Try Again
            </button>
          </div>
        ) : (
          <button
            className={btn}
            disabled={answers.includes(-1) || submitting}
            onClick={handleSubmit}
          >
            {submitting ? (
              <span className="flex items-center gap-2">
                <svg className="h-4 w-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Submitting…
              </span>
            ) : "Submit Answers"}
          </button>
        )
      )}

      {/* Past attempts */}
      {history.length > 0 && (
        <div className={card}>
          <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">
            📅 Past Attempts
          </h3>
          <div className="space-y-1.5">
            {history.map((h, i) => (
              <div key={i} className="flex items-center justify-between rounded-lg bg-[#0a1628] px-3 py-2 text-sm">
                <span className="text-slate-400">{new Date(h.created_at).toLocaleString()}</span>
                <span className="font-semibold text-cyan-300">{h.score}/{h.total}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
