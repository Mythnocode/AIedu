CREATE TABLE IF NOT EXISTS students (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  student_no TEXT NOT NULL,
  name TEXT NOT NULL,
  class_name TEXT NOT NULL,
  avg_rate REAL NOT NULL,
  total_questions INTEGER NOT NULL,
  kp_data TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE(user_id, student_no)
);

CREATE INDEX IF NOT EXISTS idx_students_user_class ON students(user_id, class_name);
CREATE INDEX IF NOT EXISTS idx_students_user_updated ON students(user_id, updated_at);
