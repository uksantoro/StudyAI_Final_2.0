const Database = require("better-sqlite3");

const db = new Database("./studyai.sqlite");

const rows = db.prepare(`
  SELECT feature, COALESCE(SUM(units), 0) AS used
  FROM ai_usage
  WHERE user_id = 1
    AND created_at >= date('now', 'start of month')
  GROUP BY feature
  ORDER BY feature
`).all();

console.table(rows);

db.close();
