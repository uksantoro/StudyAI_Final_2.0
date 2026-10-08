require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.JWT_SECRET || "studyai-final-dev-secret-change-me";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "studyai.sqlite");
const UPLOAD_DIR = path.join(__dirname, process.env.UPLOAD_DIR || "uploads");
const MAX_AUDIO_MB = Number(process.env.MAX_AUDIO_MB || 250);

fs.mkdirSync(UPLOAD_DIR, {recursive:true});
const db = new Database(DB_PATH);
db.pragma("foreign_keys = ON");
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 name TEXT DEFAULT 'Studente',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS courses(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 university TEXT DEFAULT '',
 color TEXT DEFAULT '#6d4aff',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS subjects(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 course_id INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 color TEXT DEFAULT '#6d4aff',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS lessons(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
 title TEXT NOT NULL,
 lesson_number TEXT DEFAULT '',
 date TEXT DEFAULT '',
 duration INTEGER DEFAULT 0,
 audio_path TEXT,
 audio_name TEXT,
 transcript TEXT DEFAULT '',
 summary TEXT DEFAULT '',
 concepts TEXT DEFAULT '',
 completed INTEGER DEFAULT 0,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notes(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 lesson_id INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
 body TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS flashcards(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 lesson_id INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
 question TEXT NOT NULL,
 answer TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS quiz_questions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 lesson_id INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
 question TEXT NOT NULL,
 options TEXT NOT NULL,
 answer_index INTEGER NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS study_events(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 lesson_id INTEGER REFERENCES lessons(id) ON DELETE CASCADE,
 kind TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

const upload = multer({
  storage: multer.diskStorage({
    destination: (_, __, cb) => cb(null, UPLOAD_DIR),
    filename: (_, file, cb) => {
      const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
      cb(null, Date.now() + "_" + safe);
    }
  }),
  limits: {fileSize: MAX_AUDIO_MB * 1024 * 1024},
  fileFilter: (_, file, cb) => {
    const ok = /audio\//.test(file.mimetype) || /\.(mp3|wav|m4a|ogg|webm)$/i.test(file.originalname);
    cb(ok ? null : new Error("Formato audio non supportato."), ok);
  }
});

app.use(cors());
app.use(express.json({limit:"2mb"}));
app.use(express.urlencoded({extended:true}));
app.use("/uploads", express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname, "public")));

function auth(req,res,next){
  try{
    const h=req.headers.authorization||"";
    const token=h.startsWith("Bearer ") ? h.slice(7) : "";
    if(!token) return res.status(401).json({error:"Token mancante."});
    req.user=jwt.verify(token,SECRET);
    next();
  }catch(e){ return res.status(401).json({error:"Sessione non valida."}); }
}
function requireRole(...roles){ return (req,res,next)=>{ if(!roles.includes(req.user.role)) return res.status(403).json({error:"Accesso negato."}); next(); }; }
function audit(req, action, details=""){
  try{
    db.prepare("INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)")
      .run(req.user?.id || null, action, details);
  }catch(e){
    console.error("Audit log error:", e.message);
  }
}
function sign(user){ return jwt.sign({id:user.id,email:user.email,name:user.name,role:user.role},SECRET,{expiresIn:"7d"}); }
function getCourseForUser(courseId,userId){
  return db.prepare("SELECT * FROM courses WHERE id=? AND user_id=?").get(courseId,userId);
}
function getLessonForUser(lessonId,userId){
  return db.prepare(`
    SELECT l.*, s.name subject_name, s.course_id, c.name course_name, c.university
    FROM lessons l JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id
    WHERE l.id=? AND c.user_id=?`).get(lessonId,userId);
}
function safeJson(v, fallback=[]){ try{return JSON.parse(v||"")}catch{return fallback;} }

app.get("/api/health",(req,res)=>res.json({ok:true,version:"2.0"}));

app.post("/api/auth/register",(req,res)=>{
  const email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||"");
  if(!email || password.length<6) return res.status(400).json({error:"Inserisci email e password di almeno 6 caratteri."});
  try{
    const hash=bcrypt.hashSync(password,10);
    const r=db.prepare("INSERT INTO users(email,password_hash,name) VALUES(?,?,?)").run(email,hash,email.split("@")[0]);
    const u=db.prepare("SELECT id,email,name FROM users WHERE id=?").get(r.lastInsertRowid);
    res.json({token:sign(u),user:u});
  }catch(e){res.status(400).json({error:"Email già registrata."});}
});
app.post("/api/auth/login",(req,res)=>{
  const email=String(req.body.email||"").trim().toLowerCase(), password=String(req.body.password||"");
  const u=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!u || !bcrypt.compareSync(password,u.password_hash)) return res.status(401).json({error:"Email o password non corretti."});
  res.json({token:sign(u),user:{id:u.id,email:u.email,name:u.name}});
});
app.get("/api/me",auth,(req,res)=>res.json(db.prepare("SELECT id,email,name,role,created_at FROM users WHERE id=?").get(req.user.id)));
app.get("/api/dashboard",auth,(req,res)=>{
  const courses=db.prepare("SELECT * FROM courses WHERE user_id=? ORDER BY updated_at DESC").all(req.user.id);
  const lessons=db.prepare(`
    SELECT l.id,l.title,l.lesson_number,l.date,l.completed,s.name subject_name,c.name course_name
    FROM lessons l JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id
    WHERE c.user_id=? ORDER BY l.updated_at DESC LIMIT 8`).all(req.user.id);
  const total=db.prepare(`SELECT COUNT(*) n FROM lessons l JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE c.user_id=?`).get(req.user.id).n;
  const done=db.prepare(`SELECT COUNT(*) n FROM lessons l JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE c.user_id=? AND l.completed=1`).get(req.user.id).n;
  res.json({courses,lessons,stats:{total,done,percent:total?Math.round(done*100/total):0}});
});

app.get("/api/courses",auth,(req,res)=>{
  const rows=db.prepare("SELECT c.*, (SELECT COUNT(*) FROM subjects s WHERE s.course_id=c.id) subject_count, (SELECT COUNT(*) FROM lessons l JOIN subjects s ON s.id=l.subject_id WHERE s.course_id=c.id) lesson_count FROM courses c WHERE c.user_id=? ORDER BY c.updated_at DESC").all(req.user.id);
  res.json(rows);
});
app.post("/api/courses",auth,(req,res)=>{
  const name=String(req.body.name||"").trim(); if(!name)return res.status(400).json({error:"Nome corso obbligatorio."});
  const r=db.prepare("INSERT INTO courses(user_id,name,university,color) VALUES(?,?,?,?)").run(req.user.id,name,String(req.body.university||""),String(req.body.color||"#6d4aff"));
  res.json(db.prepare("SELECT * FROM courses WHERE id=?").get(r.lastInsertRowid));
});
app.patch("/api/courses/:id",auth,(req,res)=>{
  if(!getCourseForUser(req.params.id,req.user.id))return res.status(404).json({error:"Corso non trovato."});
  db.prepare("UPDATE courses SET name=?,university=?,color=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(String(req.body.name||"").trim(),String(req.body.university||""),String(req.body.color||"#6d4aff"),req.params.id);
  res.json(db.prepare("SELECT * FROM courses WHERE id=?").get(req.params.id));
});
app.delete("/api/courses/:id",auth,(req,res)=>{
  const c=getCourseForUser(req.params.id,req.user.id); if(!c)return res.status(404).json({error:"Corso non trovato."});
  db.prepare("DELETE FROM courses WHERE id=?").run(req.params.id); res.json({ok:true});
});
app.get("/api/courses/:id",auth,(req,res)=>{
  const c=getCourseForUser(req.params.id,req.user.id); if(!c)return res.status(404).json({error:"Corso non trovato."});
  const subjects=db.prepare("SELECT s.*, (SELECT COUNT(*) FROM lessons l WHERE l.subject_id=s.id) lesson_count FROM subjects s WHERE s.course_id=? ORDER BY s.created_at DESC").all(c.id);
  res.json({course:c,subjects});
});

app.post("/api/courses/:id/subjects",auth,(req,res)=>{
  if(!getCourseForUser(req.params.id,req.user.id))return res.status(404).json({error:"Corso non trovato."});
  const name=String(req.body.name||"").trim(); if(!name)return res.status(400).json({error:"Nome materia obbligatorio."});
  const r=db.prepare("INSERT INTO subjects(course_id,name,color) VALUES(?,?,?)").run(req.params.id,name,String(req.body.color||"#6d4aff"));
  res.json(db.prepare("SELECT * FROM subjects WHERE id=?").get(r.lastInsertRowid));
});
app.patch("/api/subjects/:id",auth,(req,res)=>{
  const s=db.prepare("SELECT s.* FROM subjects s JOIN courses c ON c.id=s.course_id WHERE s.id=? AND c.user_id=?").get(req.params.id,req.user.id);
  if(!s)return res.status(404).json({error:"Materia non trovata."});
  db.prepare("UPDATE subjects SET name=?,color=? WHERE id=?").run(String(req.body.name||"").trim(),String(req.body.color||"#6d4aff"),s.id);
  res.json(db.prepare("SELECT * FROM subjects WHERE id=?").get(s.id));
});
app.delete("/api/subjects/:id",auth,(req,res)=>{
  const s=db.prepare("SELECT s.* FROM subjects s JOIN courses c ON c.id=s.course_id WHERE s.id=? AND c.user_id=?").get(req.params.id,req.user.id);
  if(!s)return res.status(404).json({error:"Materia non trovata."});
  db.prepare("DELETE FROM subjects WHERE id=?").run(s.id); res.json({ok:true});
});
app.get("/api/subjects/:id",auth,(req,res)=>{
  const s=db.prepare("SELECT s.*,c.name course_name,c.id course_id FROM subjects s JOIN courses c ON c.id=s.course_id WHERE s.id=? AND c.user_id=?").get(req.params.id,req.user.id);
  if(!s)return res.status(404).json({error:"Materia non trovata."});
  const lessons=db.prepare("SELECT id,title,lesson_number,date,duration,audio_name,completed FROM lessons WHERE subject_id=? ORDER BY created_at DESC").all(s.id);
  res.json({subject:s,lessons});
});
app.post("/api/subjects/:id/lessons",auth,(req,res)=>{
  const s=db.prepare("SELECT s.* FROM subjects s JOIN courses c ON c.id=s.course_id WHERE s.id=? AND c.user_id=?").get(req.params.id,req.user.id);
  if(!s)return res.status(404).json({error:"Materia non trovata."});
  const title=String(req.body.title||"").trim(); if(!title)return res.status(400).json({error:"Titolo lezione obbligatorio."});
  const r=db.prepare("INSERT INTO lessons(subject_id,title,lesson_number,date) VALUES(?,?,?,?)").run(s.id,title,String(req.body.lesson_number||""),String(req.body.date||""));
  res.json(db.prepare("SELECT * FROM lessons WHERE id=?").get(r.lastInsertRowid));
});

app.get("/api/lessons/:id",auth,(req,res)=>{
  const l=getLessonForUser(req.params.id,req.user.id); if(!l)return res.status(404).json({error:"Lezione non trovata."});
  const notes=db.prepare("SELECT * FROM notes WHERE lesson_id=? ORDER BY updated_at DESC").all(l.id);
  const flashcards=db.prepare("SELECT * FROM flashcards WHERE lesson_id=? ORDER BY id DESC").all(l.id);
  const questions=db.prepare("SELECT * FROM quiz_questions WHERE lesson_id=? ORDER BY id DESC").all(l.id).map(q=>({...q,options:safeJson(q.options,[])}));
  res.json({lesson:l,notes,flashcards,questions});
});
app.patch("/api/lessons/:id",auth,(req,res)=>{
  const l=getLessonForUser(req.params.id,req.user.id); if(!l)return res.status(404).json({error:"Lezione non trovata."});
  const fields=["title","lesson_number","date","transcript","summary","concepts"];
  const data=Object.fromEntries(fields.map(k=>[k,req.body[k]!==undefined?String(req.body[k]):l[k]]));
  const completed=req.body.completed!==undefined ? (req.body.completed?1:0) : l.completed;
  db.prepare("UPDATE lessons SET title=?,lesson_number=?,date=?,transcript=?,summary=?,concepts=?,completed=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(data.title,data.lesson_number,data.date,data.transcript,data.summary,data.concepts,completed,l.id);
  res.json(db.prepare("SELECT * FROM lessons WHERE id=?").get(l.id));
});
app.delete("/api/lessons/:id",auth,(req,res)=>{
  const l=getLessonForUser(req.params.id,req.user.id); if(!l)return res.status(404).json({error:"Lezione non trovata."});
  if(l.audio_path) try{fs.unlinkSync(path.join(__dirname,l.audio_path.replace(/^uploads[\\/]/,"")));}catch{}
  db.prepare("DELETE FROM lessons WHERE id=?").run(l.id); res.json({ok:true});
});
app.post("/api/lessons/:id/audio",auth,upload.single("audio"),(req,res)=>{
  const l=getLessonForUser(req.params.id,req.user.id); if(!l)return res.status(404).json({error:"Lezione non trovata."});
  if(!req.file)return res.status(400).json({error:"File audio mancante."});
  if(l.audio_path) try{fs.unlinkSync(path.join(__dirname,l.audio_path.replace(/^uploads[\\/]/,"")));}catch{}
  const rel=path.join("uploads",req.file.filename);
  db.prepare("UPDATE lessons SET audio_path=?,audio_name=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(rel,req.file.originalname,l.id);
  res.json({ok:true,audio_name:req.file.originalname,audio_url:"/"+rel.replace(/\\/g,"/")});
});
app.delete("/api/lessons/:id/audio",auth,(req,res)=>{
  const l=getLessonForUser(req.params.id,req.user.id); if(!l)return res.status(404).json({error:"Lezione non trovata."});
  if(l.audio_path) try{fs.unlinkSync(path.join(__dirname,l.audio_path.replace(/^uploads[\\/]/,"")));}catch{}
  db.prepare("UPDATE lessons SET audio_path=NULL,audio_name=NULL,duration=0 WHERE id=?").run(l.id); res.json({ok:true});
});

app.post("/api/lessons/:id/notes",auth,(req,res)=>{
  const l=getLessonForUser(req.params.id,req.user.id); if(!l)return res.status(404).json({error:"Lezione non trovata."});
  const body=String(req.body.body||"").trim(); if(!body)return res.status(400).json({error:"Nota vuota."});
  const r=db.prepare("INSERT INTO notes(lesson_id,body) VALUES(?,?)").run(l.id,body); res.json(db.prepare("SELECT * FROM notes WHERE id=?").get(r.lastInsertRowid));
});
app.patch("/api/notes/:id",auth,(req,res)=>{
  const n=db.prepare("SELECT n.* FROM notes n JOIN lessons l ON l.id=n.lesson_id JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE n.id=? AND c.user_id=?").get(req.params.id,req.user.id);
  if(!n)return res.status(404).json({error:"Nota non trovata."});
  db.prepare("UPDATE notes SET body=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(String(req.body.body||""),n.id); res.json(db.prepare("SELECT * FROM notes WHERE id=?").get(n.id));
});
app.delete("/api/notes/:id",auth,(req,res)=>{
  const n=db.prepare("SELECT n.id FROM notes n JOIN lessons l ON l.id=n.lesson_id JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE n.id=? AND c.user_id=?").get(req.params.id,req.user.id);
  if(!n)return res.status(404).json({error:"Nota non trovata."}); db.prepare("DELETE FROM notes WHERE id=?").run(n.id); res.json({ok:true});
});

app.post("/api/lessons/:id/flashcards",auth,(req,res)=>{
  const l=getLessonForUser(req.params.id,req.user.id); if(!l)return res.status(404).json({error:"Lezione non trovata."});
  const q=String(req.body.question||"").trim(), a=String(req.body.answer||"").trim(); if(!q||!a)return res.status(400).json({error:"Domanda e risposta obbligatorie."});
  const r=db.prepare("INSERT INTO flashcards(lesson_id,question,answer) VALUES(?,?,?)").run(l.id,q,a); res.json(db.prepare("SELECT * FROM flashcards WHERE id=?").get(r.lastInsertRowid));
});
app.patch("/api/flashcards/:id",auth,(req,res)=>{
  const f=db.prepare("SELECT f.* FROM flashcards f JOIN lessons l ON l.id=f.lesson_id JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE f.id=? AND c.user_id=?").get(req.params.id,req.user.id);
  if(!f)return res.status(404).json({error:"Flashcard non trovata."});
  db.prepare("UPDATE flashcards SET question=?,answer=? WHERE id=?").run(String(req.body.question||""),String(req.body.answer||""),f.id); res.json(db.prepare("SELECT * FROM flashcards WHERE id=?").get(f.id));
});
app.delete("/api/flashcards/:id",auth,(req,res)=>{
  const f=db.prepare("SELECT f.id FROM flashcards f JOIN lessons l ON l.id=f.lesson_id JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE f.id=? AND c.user_id=?").get(req.params.id,req.user.id);
  if(!f)return res.status(404).json({error:"Flashcard non trovata."}); db.prepare("DELETE FROM flashcards WHERE id=?").run(f.id); res.json({ok:true});
});

app.post("/api/lessons/:id/questions",auth,(req,res)=>{
  const l=getLessonForUser(req.params.id,req.user.id); if(!l)return res.status(404).json({error:"Lezione non trovata."});
  const question=String(req.body.question||"").trim(), options=Array.isArray(req.body.options)?req.body.options.map(String):[], answer_index=Number(req.body.answer_index);
  if(!question||options.length<2||!Number.isInteger(answer_index)||answer_index<0||answer_index>=options.length)return res.status(400).json({error:"Domanda, almeno 2 opzioni e risposta corretta obbligatorie."});
  const r=db.prepare("INSERT INTO quiz_questions(lesson_id,question,options,answer_index) VALUES(?,?,?,?)").run(l.id,question,JSON.stringify(options),answer_index);
  res.json({...db.prepare("SELECT * FROM quiz_questions WHERE id=?").get(r.lastInsertRowid),options});
});
app.delete("/api/questions/:id",auth,(req,res)=>{
  const q=db.prepare("SELECT q.id FROM quiz_questions q JOIN lessons l ON l.id=q.lesson_id JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE q.id=? AND c.user_id=?").get(req.params.id,req.user.id);
  if(!q)return res.status(404).json({error:"Domanda non trovata."}); db.prepare("DELETE FROM quiz_questions WHERE id=?").run(q.id); res.json({ok:true});
});
app.post("/api/study-events",auth,(req,res)=>{
  db.prepare("INSERT INTO study_events(user_id,lesson_id,kind) VALUES(?,?,?)").run(req.user.id,req.body.lesson_id||null,String(req.body.kind||"study")); res.json({ok:true});
});
app.get("/api/stats",auth,(req,res)=>{
  const courses=db.prepare("SELECT COUNT(*) n FROM courses WHERE user_id=?").get(req.user.id).n;
  const subjects=db.prepare("SELECT COUNT(*) n FROM subjects s JOIN courses c ON c.id=s.course_id WHERE c.user_id=?").get(req.user.id).n;
  const lessons=db.prepare("SELECT COUNT(*) n FROM lessons l JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE c.user_id=?").get(req.user.id).n;
  const completed=db.prepare("SELECT COUNT(*) n FROM lessons l JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE c.user_id=? AND l.completed=1").get(req.user.id).n;
  const audio=db.prepare("SELECT COUNT(*) n FROM lessons l JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE c.user_id=? AND l.audio_path IS NOT NULL").get(req.user.id).n;
  const events=db.prepare("SELECT kind,COUNT(*) n FROM study_events WHERE user_id=? GROUP BY kind ORDER BY n DESC").all(req.user.id);
  res.json({courses,subjects,lessons,completed,audio,percent:lessons?Math.round(completed*100/lessons):0,events});
});
app.get("/api/search",auth,(req,res)=>{
  const q="%"+String(req.query.q||"").trim()+"%"; if(q.length<3)return res.json([]);
  const rows=db.prepare(`
    SELECT 'course' type,c.id,c.name title,'' subtitle FROM courses c WHERE c.user_id=? AND c.name LIKE ?
    UNION ALL
    SELECT 'subject',s.id,s.name,c.name FROM subjects s JOIN courses c ON c.id=s.course_id WHERE c.user_id=? AND s.name LIKE ?
    UNION ALL
    SELECT 'lesson',l.id,l.title,s.name FROM lessons l JOIN subjects s ON s.id=l.subject_id JOIN courses c ON c.id=s.course_id WHERE c.user_id=? AND (l.title LIKE ? OR l.transcript LIKE ? OR l.summary LIKE ?)
    LIMIT 30`).all(req.user.id,q,req.user.id,q,req.user.id,q,q,q);
  res.json(rows);
});

app.post("/api/lessons/:id/demo-ai",auth,(req,res)=>{
  const l=getLessonForUser(req.params.id,req.user.id); if(!l)return res.status(404).json({error:"Lezione non trovata."});
  const text=(l.transcript||"").trim();
  if(!text) return res.status(400).json({error:"Inserisci prima una trascrizione. Questa è una funzione demo locale, senza AI esterna."});
  const sentences=text.split(/(?<=[.!?])\s+/).filter(Boolean);
  const summary=sentences.slice(0,5).join(" ");
  const concepts=[...new Set(text.toLowerCase().match(/\b[a-zà-ÿ]{7,}\b/g)||[])].slice(0,8).join(", ");
  db.prepare("UPDATE lessons SET summary=?,concepts=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").run(summary,concepts,l.id);
  res.json({summary,concepts});
});

app.get("/api/admin/test",auth,requireRole("ADMIN","SUPER_ADMIN"),(req,res)=>{
  audit(req,"ADMIN_TEST","Accesso al test admin");
  res.json({ok:true,role:req.user.role});
});

app.get("/api/admin/users",auth,requireRole("ADMIN","SUPER_ADMIN"),(req,res)=>{
  const users=db.prepare(`
    SELECT id,email,name,role,created_at
    FROM users
    ORDER BY id DESC
  `).all();

    res.json(users);
});

app.get("/api/admin/users",auth,requireRole("ADMIN","SUPER_ADMIN"),(req,res)=>{
  const users=db.prepare(`
    SELECT id,email,name,role,created_at
    FROM users
    ORDER BY id DESC
  `).all();

  res.json(users);
});

app.get("/api/admin/users/:id/subscription",auth,requireRole("ADMIN","SUPER_ADMIN"),(req,res)=>{
  const userId=Number(req.params.id);

  if(!Number.isInteger(userId)){
    return res.status(400).json({error:"ID utente non valido."});
  }

  const user=db.prepare(`
    SELECT id,email,name,role,created_at
    FROM users
    WHERE id=?
  `).get(userId);

  if(!user){
    return res.status(404).json({error:"Utente non trovato."});
  }

  const subscription=db.prepare(`
    SELECT
      id,
      user_id,
      plan,
      status,
      started_at,
      expires_at,
      amount,
      auto_renew,
      created_at
    FROM subscriptions
    WHERE user_id=?
    ORDER BY id DESC
    LIMIT 1
  `).get(userId);

  res.json(subscription||null);
});
app.get("/api/admin/subscriptions",auth,requireRole("ADMIN","SUPER_ADMIN"),(req,res)=>{
  const subscriptions=db.prepare(`
    SELECT
      s.id,
      s.user_id,
      u.email,
      u.name,
      s.plan,
      s.status,
      s.started_at,
      s.expires_at,
      s.amount,
      s.auto_renew,
      s.created_at
    FROM subscriptions s
    LEFT JOIN users u ON u.id=s.user_id
    ORDER BY s.id DESC
  `).all();

  res.json(subscriptions);
});
app.get("/api/admin/audit-logs",auth,requireRole("ADMIN","SUPER_ADMIN"),(req,res)=>{
  const logs=db.prepare(`
    SELECT a.id,a.user_id,a.action,a.details,a.created_at,u.email
    FROM audit_logs a
    LEFT JOIN users u ON u.id=a.user_id
    ORDER BY a.id DESC
    LIMIT 100
  `).all();

  res.json(logs);
});

app.use((err,req,res,next)=>{
  if(err && err.message) return res.status(400).json({error:err.message});
  res.status(500).json({error:"Errore interno."});
});
app.get("/api/admin/subscriptions",auth,requireRole("ADMIN","SUPER_ADMIN"),(req,res)=>{
  const subscriptions=db.prepare(`
    SELECT
      s.id,
      s.user_id,
      u.email,
      u.name,
      s.plan,
      s.status,
      s.started_at,
      s.expires_at,
      s.amount,
      s.auto_renew,
      s.created_at
    FROM subscriptions s
    LEFT JOIN users u ON u.id=s.user_id
    ORDER BY s.id DESC
  `).all();

  res.json(subscriptions);
});
app.get("/api/admin/subscriptions",auth,requireRole("ADMIN","SUPER_ADMIN"),(req,res)=>{
  const subscriptions=db.prepare(`
    SELECT
      s.id,
      s.user_id,
      u.email,
      u.name,
      s.plan,
      s.status,
      s.started_at,
      s.expires_at,
      s.amount,
      s.auto_renew,
      s.created_at
    FROM subscriptions s
    LEFT JOIN users u ON u.id=s.user_id
    ORDER BY s.id DESC
  `).all();

  res.json(subscriptions);
});
app.get("/*splat",(req,res)=>{
  res.sendFile(path.join(__dirname,"public","index.html"));
});

app.listen(PORT,()=>console.log(`StudyAI Final 2.0: http://localhost:${PORT}`));



