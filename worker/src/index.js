const MAX_FILES = 6;
const MAX_FILE_SIZE = 4 * 1024 * 1024;
const MAX_TOTAL_FILE_SIZE = 8 * 1024 * 1024;
const MAX_ANALYSIS_TEXT_LENGTH = 18e3;
const SESSION_COOKIE = "exam_analyzer_session";
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const PASSWORD_ITERATIONS = 1e5;
var index_default = {
  async fetch(request, env) {
    const corsHeaders = getCorsHeaders(env, request);
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/health" && request.method === "GET") {
        return json({ ok: true }, 200, corsHeaders);
      }
      if (url.pathname === "/api/auth/register" && request.method === "POST") {
        return await handleRegister(request, env, corsHeaders);
      }
      if (url.pathname === "/api/auth/login" && request.method === "POST") {
        return await handleLogin(request, env, corsHeaders);
      }
      if (url.pathname === "/api/auth/logout" && request.method === "POST") {
        return await handleLogout(request, env, corsHeaders);
      }
      if (url.pathname === "/api/auth/me" && request.method === "GET") {
        const user = await getCurrentUser(request, env);
        return json({ user }, 200, corsHeaders);
      }
      if (url.pathname === "/api/auth/profile" && request.method === "POST") {
        const user = await requireUser(request, env);
        return await handleUpdateProfile(request, env, corsHeaders, user);
      }
      if (url.pathname === "/api/papers/analyze" && request.method === "POST") {
        const user = await requireUser(request, env);
        return await handleAnalyzePaper(request, env, corsHeaders, user);
      }
      if (url.pathname === "/api/papers/grade" && request.method === "POST") {
        const user = await requireUser(request, env);
        return await handleGradePaper(request, env, corsHeaders, user);
      }
      if (url.pathname === "/api/essay/grade" && request.method === "POST") {
        const user = await requireUser(request, env);
        return await handleEssayGrading(request, env, corsHeaders, user);
      }
      if (url.pathname === "/api/questions" && request.method === "GET") {
        const user = await requireUser(request, env);
        return await handleListQuestions(env, corsHeaders, user);
      }
      if (url.pathname === "/api/questions/clear" && request.method === "POST") {
        const user = await requireUser(request, env);
        return await handleClearQuestions(env, corsHeaders, user);
      }
      if (url.pathname === "/api/students" && request.method === "GET") {
        const user = await requireUser(request, env);
        return await handleListStudents(env, corsHeaders, user);
      }
      if (url.pathname === "/api/students" && request.method === "POST") {
        const user = await requireUser(request, env);
        return await handleCreateStudent(request, env, corsHeaders, user);
      }
      if (url.pathname === "/api/students" && request.method === "DELETE") {
        const user = await requireUser(request, env);
        return await handleDeleteStudent(request, env, corsHeaders, user);
      }
      if (url.pathname === "/api/students" && request.method === "PUT") {
        const user = await requireUser(request, env);
        return await handleUpdateStudent(request, env, corsHeaders, user);
      }
      return json({ message: "Not found" }, 404, corsHeaders);
    } catch (error) {
      if (error instanceof AuthError) {
        return json({ message: error.message }, 401, corsHeaders);
      }
      if (error instanceof HttpError) {
        return json({ message: error.message }, error.status, corsHeaders);
      }
      return json({ message: getErrorMessage(error, "\u670D\u52A1\u6682\u65F6\u4E0D\u53EF\u7528\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\u3002") }, 500, corsHeaders);
    }
  }
};
async function handleRegister(request, env, corsHeaders) {
  assertDatabaseConfigured(env);
  const payload = await request.json().catch(() => null);
  const email = normalizeEmail(payload?.email);
  const password = typeof payload?.password === "string" ? payload.password : "";
  const name = normalizeName(payload?.name, email);
  if (!email || !isValidEmail(email)) {
    throw new HttpError(400, "\u8BF7\u8F93\u5165\u6709\u6548\u90AE\u7BB1\u3002");
  }
  if (password.length < 8) {
    throw new HttpError(400, "\u5BC6\u7801\u81F3\u5C11\u9700\u8981 8 \u4F4D\u3002");
  }
  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (existing) {
    throw new HttpError(409, "\u8BE5\u90AE\u7BB1\u5DF2\u6CE8\u518C\uFF0C\u8BF7\u76F4\u63A5\u767B\u5F55\u3002");
  }
  const userId = crypto.randomUUID();
  const passwordRecord = await hashPassword(password);
  const now = (/* @__PURE__ */ new Date()).toISOString();
  await env.DB.prepare(
    "INSERT INTO users (id, email, name, password_hash, password_salt, password_iterations, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(userId, email, name, passwordRecord.hash, passwordRecord.salt, PASSWORD_ITERATIONS, now, now).run();
  return withSessionCookie(request, env, corsHeaders, { id: userId, email, name, createdAt: now });
}
async function handleLogin(request, env, corsHeaders) {
  assertDatabaseConfigured(env);
  const payload = await request.json().catch(() => null);
  const email = normalizeEmail(payload?.email);
  const password = typeof payload?.password === "string" ? payload.password : "";
  if (!email || !password) {
    throw new HttpError(400, "\u8BF7\u8F93\u5165\u90AE\u7BB1\u548C\u5BC6\u7801\u3002");
  }
  const row = await env.DB.prepare(
    "SELECT id, email, name, password_hash, password_salt, password_iterations, created_at FROM users WHERE email = ?"
  ).bind(email).first();
  if (!row || !await verifyPassword(password, row.password_salt, row.password_hash, row.password_iterations)) {
    throw new HttpError(401, "\u90AE\u7BB1\u6216\u5BC6\u7801\u4E0D\u6B63\u786E\u3002");
  }
  return withSessionCookie(request, env, corsHeaders, {
    id: row.id,
    email: row.email,
    name: row.name,
    createdAt: row.created_at
  });
}
async function handleLogout(request, env, corsHeaders) {
  assertDatabaseConfigured(env);
  const token = getCookie(request, SESSION_COOKIE);
  if (token) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256Hex(token)).run();
  }
  return json(
    { ok: true },
    200,
    {
      ...corsHeaders,
      "Set-Cookie": clearSessionCookie(request)
    }
  );
}
async function handleUpdateProfile(request, env, corsHeaders, user) {
  const payload = await request.json().catch(() => null);
  const name = typeof payload?.name === "string" ? payload.name.trim() : "";
  const currentPassword = typeof payload?.currentPassword === "string" ? payload.currentPassword : "";
  const newPassword = typeof payload?.newPassword === "string" ? payload.newPassword : "";
  const now = (/* @__PURE__ */ new Date()).toISOString();
  if (name) {
    await env.DB.prepare("UPDATE users SET name = ?, updated_at = ? WHERE id = ?").bind(name, now, user.id).run();
  }
  if (newPassword) {
    if (newPassword.length < 8) {
      throw new HttpError(400, "\u65B0\u5BC6\u7801\u81F3\u5C11\u9700\u8981 8 \u4F4D\u3002");
    }
    const row = await env.DB.prepare(
      "SELECT password_hash, password_salt, password_iterations FROM users WHERE id = ?"
    ).bind(user.id).first();
    if (!row || !await verifyPassword(currentPassword, row.password_salt, row.password_hash, row.password_iterations)) {
      throw new HttpError(401, "\u5F53\u524D\u5BC6\u7801\u4E0D\u6B63\u786E\u3002");
    }
    const passwordRecord = await hashPassword(newPassword);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ? WHERE id = ?"
    ).bind(passwordRecord.hash, passwordRecord.salt, PASSWORD_ITERATIONS, now, user.id).run();
  }
  const updated = await getUserById(env, user.id);
  return json({ user: updated }, 200, corsHeaders);
}
async function handleAnalyzePaper(request, env, corsHeaders, user) {
  const formData = await request.formData();
  const mode = String(formData.get("mode") || "default");
  const title = String(formData.get("title") || "").trim();
  const files = [];
  for (const entry of formData.getAll("files")) {
    if (isUploadedFile(entry)) files.push(entry);
  }
  const textParts = formData.getAll("texts").filter((value) => typeof value === "string").map((value) => value.trim()).filter(Boolean);
  if (mode !== "default" && mode !== "multimodal") {
    throw new HttpError(400, "\u5206\u6790\u65B9\u5F0F\u4E0D\u6B63\u786E\u3002");
  }
  if (files.length === 0 && textParts.length === 0) {
    throw new HttpError(400, "\u8BF7\u5148\u4E0A\u4F20\u8BD5\u5377\u6587\u4EF6\u3002");
  }
  if (files.length > MAX_FILES) {
    throw new HttpError(400, `\u4E00\u6B21\u6700\u591A\u5206\u6790 ${MAX_FILES} \u4E2A\u6587\u4EF6\u3002`);
  }
  const totalFileSize = files.reduce((sum, file) => sum + file.size, 0);
  if (totalFileSize > MAX_TOTAL_FILE_SIZE) {
    throw new HttpError(400, "\u672C\u6B21\u5F85\u5206\u6790\u6587\u4EF6\u603B\u5927\u5C0F\u8D85\u8FC7 8MB\uFF0C\u8BF7\u51CF\u5C11\u9875\u6570\u6216\u538B\u7F29\u540E\u91CD\u8BD5\u3002");
  }
  for (const file of files) {
    validateUploadedFile(file);
  }
  let result;
  let provider;
  if (mode === "default") {
    assertBaiduConfigured(env);
    assertDeepSeekConfigured(env);
    const combinedText = await buildDefaultAnalysisText(files, textParts, env);
    result = await analyzeWithDeepSeek(combinedText, env);
    result.originalTextPreview = combinedText.slice(0, 1200);
    provider = "baidu-ocr+deepseek";
  } else {
    assertOpenAiConfigured(env);
    assertDeepSeekConfigured(env);
    const extractedText = await extractTextWithGPTVision(files, textParts, env);
    result = await analyzeWithDeepSeek(extractedText, env);
    result.originalTextPreview = extractedText.slice(0, 1200);
    provider = "gpt-vision+deepseek";
  }
  const paper = await savePaperResult(env, user, {
    title: title || inferPaperTitle(files),
    mode,
    provider,
    files,
    textParts,
    result
  });
  return json({ paper, result }, 200, corsHeaders);
}
async function handleGradePaper(request, env, corsHeaders, user) {
  const formData = await request.formData();
  const files = [];
  for (const entry of formData.getAll("files")) {
    if (isUploadedFile(entry)) files.push(entry);
  }
  if (files.length === 0) {
    throw new HttpError(400, "\u8BF7\u5148\u4E0A\u4F20\u8BD5\u5377\u56FE\u7247\u518D\u8FDB\u884C\u6279\u6539\u3002");
  }
  if (files.length > MAX_FILES) {
    throw new HttpError(400, `\u4E00\u6B21\u6700\u591A\u6279\u6539 ${MAX_FILES} \u5F20\u56FE\u7247\u3002`);
  }
  const totalFileSize = files.reduce((sum, file) => sum + file.size, 0);
  if (totalFileSize > MAX_TOTAL_FILE_SIZE) {
    throw new HttpError(400, "\u56FE\u7247\u603B\u5927\u5C0F\u8D85\u8FC7 8MB\uFF0C\u8BF7\u51CF\u5C11\u9875\u6570\u6216\u538B\u7F29\u540E\u91CD\u8BD5\u3002");
  }
  for (const file of files) {
    validateUploadedFile(file);
  }
  assertOpenAiConfigured(env);
  assertDeepSeekConfigured(env);
  const recognizedText = await extractPaperContentWithVision(files, env);
  const gradeResult = await gradeWithDeepSeek(recognizedText, env);
  await updateQuestionScores(env, user, gradeResult.questions);
  await logUsage(env, user.id, "paper_grade", "gpt-vision+deepseek", `Graded ${gradeResult.questions.length} questions`);
  return json({ result: gradeResult }, 200, corsHeaders);
}
async function handleEssayGrading(request, env, corsHeaders, user) {
  const payload = await request.json().catch(() => null);
  const title = String(payload?.title || "").trim();
  const content = String(payload?.content || "").trim();
  if (content.length < 50) {
    throw new HttpError(400, "\u4F5C\u6587\u6B63\u6587\u81F3\u5C11\u9700\u898150\u5B57\u3002");
  }
  if (content.length > 1e4) {
    throw new HttpError(400, "\u4F5C\u6587\u6B63\u6587\u8FC7\u957F\uFF0C\u8BF7\u63A7\u5236\u572810000\u5B57\u4EE5\u5185\u3002");
  }
  assertDeepSeekConfigured(env);
  const result = await gradeEssayWithDeepSeek(title, content, env);
  await logUsage(env, user.id, "essay_grade", "deepseek", JSON.stringify({ title: title.slice(0, 60), wordCount: content.length, totalScore: result.totalScore }));
  return json({ result }, 200, corsHeaders);
}
async function gradeEssayWithDeepSeek(title, content, env) {
  const prompt = [
    "\u4F60\u662F\u4E00\u4F4D\u7ECF\u9A8C\u4E30\u5BCC\u3001\u4E25\u8C28\u8D1F\u8D23\u7684\u8BED\u6587\u6559\u5E08\uFF0C\u6B63\u5728\u6279\u6539\u5B66\u751F\u7684\u4F5C\u6587\u3002",
    "\u8BF7\u4ED4\u7EC6\u9605\u8BFB\u5B66\u751F\u7684\u4F5C\u6587\u5168\u6587\uFF0C\u57FA\u4E8E\u5B9E\u9645\u5185\u5BB9\u8D28\u91CF\u8FDB\u884C\u5BA2\u89C2\u3001\u516C\u6B63\u7684\u8BC4\u5206\u3002",
    "\u8BC4\u5206\u5FC5\u987B\u4E25\u683C\u4F9D\u636E\u4F5C\u6587\u7684\u771F\u5B9E\u6C34\u5E73\uFF0C\u4E0D\u8981\u523B\u610F\u7ED9\u9AD8\u5206\u6216\u4F4E\u5206\u3002",
    "",
    "\u8BC4\u5206\u7EF4\u5EA6\u548C\u5206\u503C\uFF1A",
    "1. \u5185\u5BB9\u7ACB\u610F\uFF08\u6EE1\u520630\u5206\uFF09\uFF1A\u8BC4\u4F30\u4E3B\u9898\u662F\u5426\u660E\u786E\u3001\u7ACB\u610F\u662F\u5426\u6DF1\u523B\u3001\u5185\u5BB9\u662F\u5426\u5145\u5B9E\u3001\u662F\u5426\u6709\u5177\u4F53\u4E8B\u4F8B\u548C\u771F\u60C5\u5B9E\u611F",
    "2. \u7ED3\u6784\u5E03\u5C40\uFF08\u6EE1\u520620\u5206\uFF09\uFF1A\u8BC4\u4F30\u6587\u7AE0\u7ED3\u6784\u662F\u5426\u5B8C\u6574\u3001\u5C42\u6B21\u662F\u5426\u6E05\u6670\u3001\u5F00\u5934\u7ED3\u5C3E\u662F\u5426\u547C\u5E94\u3001\u6BB5\u843D\u5B89\u6392\u662F\u5426\u5408\u7406\u3001\u8FC7\u6E21\u662F\u5426\u81EA\u7136",
    "3. \u8BED\u8A00\u8868\u8FBE\uFF08\u6EE1\u520630\u5206\uFF09\uFF1A\u8BC4\u4F30\u8BED\u8A00\u662F\u5426\u901A\u987A\u6D41\u7545\u3001\u7528\u8BCD\u662F\u5426\u51C6\u786E\u4E30\u5BCC\u3001\u662F\u5426\u6070\u5F53\u8FD0\u7528\u4FEE\u8F9E\u624B\u6CD5\u3001\u53E5\u5F0F\u662F\u5426\u591A\u6837\u3001\u6807\u70B9\u4F7F\u7528\u662F\u5426\u89C4\u8303",
    "4. \u521B\u65B0\u4EAE\u70B9\uFF08\u6EE1\u520620\u5206\uFF09\uFF1A\u8BC4\u4F30\u662F\u5426\u6709\u72EC\u7279\u89C6\u89D2\u3001\u662F\u5426\u6709\u751F\u52A8\u7684\u7EC6\u8282\u63CF\u5199\u3001\u662F\u5426\u6709\u521B\u610F\u548C\u60F3\u8C61\u529B\u3001\u662F\u5426\u6709\u4E2A\u6027\u5316\u8868\u8FBE",
    "",
    "\u8BC4\u5206\u6807\u51C6\uFF1A",
    "- \u5185\u5BB9\u7A7A\u6D1E\u3001\u4E3B\u9898\u4E0D\u6E05\u3001\u504F\u79BB\u9898\u610F\u7684\u4F5C\u6587\u5FC5\u987B\u4F4E\u5206\uFF08\u603B\u520640\u5206\u4EE5\u4E0B\uFF09",
    "- \u5185\u5BB9\u5145\u5B9E\u3001\u4E3B\u9898\u660E\u786E\u3001\u7ED3\u6784\u5408\u7406\u7684\u4F5C\u6587\u7ED9\u4E2D\u7B49\u5206\u6570\uFF0860-75\u5206\uFF09",
    "- \u53EA\u6709\u4E3B\u9898\u6DF1\u523B\u3001\u5185\u5BB9\u4E30\u5BCC\u3001\u8BED\u8A00\u4F18\u7F8E\u3001\u6709\u4EAE\u70B9\u7684\u4F18\u79C0\u4F5C\u6587\u624D\u80FD\u7ED9\u9AD8\u5206\uFF0880\u5206\u4EE5\u4E0A\uFF09",
    "- \u5982\u679C\u4F5C\u6587\u5185\u5BB9\u6BEB\u65E0\u903B\u8F91\u3001\u80E1\u4E71\u51D1\u5B57\u6570\u3001\u4E0E\u6807\u9898\u5B8C\u5168\u65E0\u5173\uFF0C\u603B\u5206\u5E94\u572830\u5206\u4EE5\u4E0B",
    "- \u5982\u679C\u4F5C\u6587\u5185\u5BB9\u57FA\u672C\u901A\u987A\u4F46\u5E73\u6DE1\u65E0\u5947\uFF0C\u603B\u5206\u5E94\u572850-65\u5206\u4E4B\u95F4",
    "",
    "\u8BF7\u4E25\u683C\u8F93\u51FA JSON \u5BF9\u8C61\uFF0C\u4E0D\u8981\u8F93\u51FA Markdown \u683C\u5F0F\u3002JSON \u5B57\u6BB5\u5982\u4E0B\uFF1A",
    "{",
    '  "totalScore": \u6570\u5B57(\u603B\u52060-100),',
    '  "dimensions": [',
    '    {"name":"\u5185\u5BB9\u7ACB\u610F","max":30,"score":\u6570\u5B57,"feedback":"\u8BE5\u7EF4\u5EA6\u7684\u5177\u4F53\u8BC4\u4EF7\uFF08\u5FC5\u987B\u5F15\u7528\u4F5C\u6587\u4E2D\u7684\u5B9E\u9645\u5185\u5BB9\u6765\u4F50\u8BC1\uFF09"},',
    '    {"name":"\u7ED3\u6784\u5E03\u5C40","max":20,"score":\u6570\u5B57,"feedback":"\u8BE5\u7EF4\u5EA6\u7684\u5177\u4F53\u8BC4\u4EF7"},',
    '    {"name":"\u8BED\u8A00\u8868\u8FBE","max":30,"score":\u6570\u5B57,"feedback":"\u8BE5\u7EF4\u5EA6\u7684\u5177\u4F53\u8BC4\u4EF7"},',
    '    {"name":"\u521B\u65B0\u4EAE\u70B9","max":20,"score":\u6570\u5B57,"feedback":"\u8BE5\u7EF4\u5EA6\u7684\u5177\u4F53\u8BC4\u4EF7"}',
    "  ],",
    '  "comment": "\u603B\u4F53\u8BC4\u8BED\uFF08100-200\u5B57\uFF0C\u5FC5\u987B\u5177\u4F53\u6307\u51FA\u4F5C\u6587\u7684\u4F18\u70B9\u548C\u4E0D\u8DB3\uFF0C\u5F15\u7528\u5B9E\u9645\u5185\u5BB9\uFF09",',
    '  "strengths": ["\u4F18\u70B91","\u4F18\u70B92","\u4F18\u70B93"],',
    '  "weaknesses": ["\u4E0D\u8DB31","\u4E0D\u8DB32","\u4E0D\u8DB33"],',
    '  "suggestions": ["\u6539\u8FDB\u5EFA\u8BAE1","\u6539\u8FDB\u5EFA\u8BAE2","\u6539\u8FDB\u5EFA\u8BAE3"]',
    "}",
    "",
    "\u91CD\u8981\u63D0\u793A\uFF1A",
    "1. \u5FC5\u987B\u8BA4\u771F\u9605\u8BFB\u4F5C\u6587\u5168\u6587\u540E\u518D\u8BC4\u5206\uFF0C\u4E0D\u8981\u4EC5\u51ED\u5B57\u6570\u6216\u5173\u952E\u8BCD\u7ED9\u5206",
    "2. \u8BC4\u4EF7\u5FC5\u987B\u5177\u4F53\uFF0C\u8981\u5F15\u7528\u4F5C\u6587\u4E2D\u7684\u5B9E\u9645\u53E5\u5B50\u6216\u5185\u5BB9\u6765\u4F50\u8BC1\u4F60\u7684\u8BC4\u4EF7",
    "3. \u5982\u679C\u4F5C\u6587\u5185\u5BB9\u8D28\u91CF\u5DEE\uFF08\u5982\u80E1\u4E71\u51D1\u5B57\u3001\u5185\u5BB9\u7A7A\u6D1E\u3001\u4E3B\u9898\u4E0D\u6E05\uFF09\uFF0C\u5FC5\u987B\u7ED9\u4F4E\u5206",
    "4. dimensions\u6570\u7EC4\u4E2D4\u4E2A\u7EF4\u5EA6\u7684score\u4E4B\u548C\u5FC5\u987B\u7B49\u4E8EtotalScore",
    "5. strengths/weaknesses/suggestions\u5404\u81F3\u5C112\u6761\uFF0C\u6700\u591A5\u6761",
    "",
    "\u4F5C\u6587\u6807\u9898\uFF1A" + (title || "\uFF08\u65E0\u6807\u9898\uFF09"),
    "",
    "\u4F5C\u6587\u6B63\u6587\uFF1A",
    content
  ].join("\n");
  const response = await fetch("https://api.deepseek.com/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.DEEPSEEK_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: env.DEEPSEEK_MODEL || "deepseek-chat",
      temperature: 0.3,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: "\u4F60\u662F\u4E00\u4F4D\u4E25\u8C28\u7684\u8BED\u6587\u6559\u5E08\uFF0C\u53EA\u8F93\u51FA\u7B26\u5408\u8981\u6C42\u7684 JSON \u5BF9\u8C61\u3002\u4F60\u5FC5\u987B\u57FA\u4E8E\u4F5C\u6587\u7684\u5B9E\u9645\u5185\u5BB9\u8FDB\u884C\u8BC4\u4EF7\uFF0C\u7EDD\u4E0D\u6577\u884D\u7ED9\u5206\u3002"
        },
        { role: "user", content: prompt }
      ]
    })
  });
  const respPayload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(`\u4F5C\u6587\u6279\u6539\u670D\u52A1\u8C03\u7528\u5931\u8D25\uFF1A${respPayload?.error?.message || response.statusText}`);
  }
  const respContent = respPayload?.choices?.[0]?.message?.content;
  if (!respContent) {
    throw new Error("\u4F5C\u6587\u6279\u6539\u670D\u52A1\u672A\u8FD4\u56DE\u6709\u6548\u7ED3\u679C\u3002");
  }
  return normalizeEssayResult(parseJsonObject(respContent), content, title);
}
function normalizeEssayResult(value, content, title) {
  const dimNames = [
    { name: "\u5185\u5BB9\u7ACB\u610F", max: 30 },
    { name: "\u7ED3\u6784\u5E03\u5C40", max: 20 },
    { name: "\u8BED\u8A00\u8868\u8FBE", max: 30 },
    { name: "\u521B\u65B0\u4EAE\u70B9", max: 20 }
  ];
  const rawDims = Array.isArray(value.dimensions) ? value.dimensions : [];
  const dimensions = dimNames.map((dim, i) => {
    const raw = rawDims[i] || {};
    let score = Math.round(Number(raw.score ?? 0));
    if (isNaN(score) || score < 0) score = 0;
    if (score > dim.max) score = dim.max;
    return {
      name: dim.name,
      max: dim.max,
      score,
      feedback: String(raw.feedback || "").trim() || "\u8BE5\u7EF4\u5EA6\u6682\u65E0\u5177\u4F53\u8BC4\u4EF7\u3002"
    };
  });
  let totalScore = dimensions.reduce((sum, d) => sum + d.score, 0);
  if (totalScore > 100) totalScore = 100;
  if (totalScore < 0) totalScore = 0;
  const grade = totalScore >= 90 ? "A \xB7 \u4F18\u79C0" : totalScore >= 80 ? "B \xB7 \u826F\u597D" : totalScore >= 70 ? "C \xB7 \u4E2D\u7B49" : totalScore >= 60 ? "D \xB7 \u53CA\u683C" : "E \xB7 \u4E0D\u53CA\u683C";
  const comment = String(value.comment || "").trim() || `\u672C\u6587\uFF08${title ? "\u300A" + title + "\u300B" : "\u65E0\u6807\u9898"}\uFF09\u5171${content.length}\u5B57\uFF0C\u603B\u5206${totalScore}\u5206\u3002\u8BF7\u53C2\u8003\u5404\u7EF4\u5EA6\u8BC4\u4EF7\u8FDB\u884C\u6539\u8FDB\u3002`;
  const toStringArray = (arr, fallback) => {
    if (!Array.isArray(arr)) return fallback;
    const result = arr.map((item) => String(item || "").trim()).filter(Boolean).slice(0, 5);
    return result.length >= 2 ? result : fallback;
  };
  return {
    totalScore,
    grade,
    dimensions,
    comment,
    strengths: toStringArray(value.strengths, ["\u6682\u65E0\u660E\u663E\u4F18\u70B9"]),
    weaknesses: toStringArray(value.weaknesses, ["\u6682\u65E0\u5177\u4F53\u4E0D\u8DB3"]),
    suggestions: toStringArray(value.suggestions, ["\u5EFA\u8BAE\u591A\u8BFB\u591A\u5199\uFF0C\u6301\u7EED\u63D0\u5347\u5199\u4F5C\u6C34\u5E73"])
  };
}
async function extractPaperContentWithVision(files, env) {
  const parts = [];
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    if (!file.type.startsWith("image/")) continue;
    const imageBase64 = await fileToBase64(file);
    const mimeType = file.type || "image/jpeg";
    const dataUrl = `data:${mimeType};base64,${imageBase64}`;
    const response = await fetch(`${(env.GPT_API_BASE || "https://geekspace.cloud/v1").replace(/\/+$/, "")}/chat/completions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GEEKSPACE_API_KEY || env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: env.OPENAI_MODEL || "gpt-5.5",
        temperature: 0.1,
        messages: [
          {
            role: "system",
            content: "\u4F60\u662F\u4E00\u4E2A\u4E13\u4E1A\u7684\u8BD5\u5377\u8BC6\u522B\u52A9\u624B\u3002\u4F60\u9700\u8981\u4ED4\u7EC6\u8BC6\u522B\u8BD5\u5377\u56FE\u7247\u4E2D\u7684\u6240\u6709\u5185\u5BB9\uFF0C\u5305\u62EC\u5370\u5237\u7684\u9898\u76EE\u548C\u624B\u5199\u7684\u7B54\u6848\u3002\u8BF7\u4E25\u683C\u6309\u7167\u8981\u6C42\u8F93\u51FA\u3002"
          },
          {
            role: "user",
            content: [
              {
                type: "text",
                text: [
                  "\u8BF7\u4ED4\u7EC6\u8BC6\u522B\u8FD9\u5F20\u8BD5\u5377\u56FE\u7247\uFF08\u7B2C" + (i + 1) + "\u9875\uFF09\u4E2D\u7684\u6240\u6709\u5185\u5BB9\u3002",
                  "",
                  "\u8BC6\u522B\u8981\u6C42\uFF1A",
                  "1. \u8BC6\u522B\u6BCF\u9053\u9898\u7684\u9898\u53F7\u3001\u9898\u578B\u3001\u9898\u76EE\u5185\u5BB9",
                  "2. \u8BC6\u522B\u5B66\u751F\u5728\u6BCF\u9053\u9898\u4E0A\u624B\u5199\u7684\u7B54\u6848\uFF08\u5305\u62EC\u624B\u5199\u6570\u5B57\u3001\u6587\u5B57\u3001\u7B97\u5F0F\u3001\u56FE\u5F62\u6807\u6CE8\u7B49\uFF09",
                  "3. \u5982\u679C\u662F\u9009\u62E9\u9898/\u5224\u65AD\u9898\uFF0C\u8BC6\u522B\u5B66\u751F\u9009\u62E9\u7684\u9009\u9879\uFF08A/B/C/D \u6216 \u221A/\xD7\uFF09",
                  "4. \u5982\u679C\u662F\u586B\u7A7A\u9898\uFF0C\u8BC6\u522B\u5B66\u751F\u586B\u5199\u7684\u7B54\u6848",
                  "5. \u5982\u679C\u662F\u89E3\u7B54\u9898/\u8BA1\u7B97\u9898\uFF0C\u8BC6\u522B\u5B66\u751F\u5B8C\u6574\u7684\u89E3\u7B54\u8FC7\u7A0B",
                  "6. \u65E0\u8BBA\u662F\u5370\u5237\u4F53\u8FD8\u662F\u624B\u5199\u4F53\uFF0C\u90FD\u8981\u5C3D\u53EF\u80FD\u51C6\u786E\u5730\u8BC6\u522B",
                  "",
                  "\u8F93\u51FA\u683C\u5F0F\uFF08\u6BCF\u9053\u9898\u7528\u5982\u4E0B\u683C\u5F0F\uFF09\uFF1A",
                  "\u3010\u9898\u53F7\u3011\u7B2CX\u9898",
                  "\u3010\u9898\u578B\u3011\u9009\u62E9\u9898/\u586B\u7A7A\u9898/\u5224\u65AD\u9898/\u89E3\u7B54\u9898/\u8BA1\u7B97\u9898/\u5176\u4ED6",
                  "\u3010\u9898\u76EE\u3011\u5B8C\u6574\u7684\u9898\u76EE\u5185\u5BB9",
                  '\u3010\u5B66\u751F\u7B54\u6848\u3011\u5B66\u751F\u5199\u4E0B\u7684\u7B54\u6848\uFF08\u5982\u679C\u672A\u4F5C\u7B54\u5219\u5199"\u672A\u4F5C\u7B54"\uFF09',
                  "---",
                  "",
                  "\u8BF7\u9010\u9898\u8F93\u51FA\uFF0C\u4E0D\u8981\u9057\u6F0F\u4EFB\u4F55\u9898\u76EE\u3002\u5373\u4F7F\u624B\u5199\u5B57\u8FF9\u4E0D\u592A\u6E05\u6670\uFF0C\u4E5F\u8981\u5C3D\u529B\u8BC6\u522B\u5E76\u6807\u6CE8\u3002"
                ].join("\n")
              },
              { type: "image_url", image_url: { url: dataUrl } }
            ]
          }
        ]
      })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const errMsg = payload?.error?.message || response.statusText;
      throw new Error(`GPT \u8BD5\u5377\u8BC6\u522B\u5931\u8D25\uFF1A${errMsg.slice(0, 100)}`);
    }
    const text = payload?.choices?.[0]?.message?.content;
    if (text) {
      parts.push(text.trim());
    }
  }
  const combined = parts.join("\n\n=== \u4E0B\u4E00\u9875 ===\n\n").trim();
  if (!combined) {
    throw new Error("\u672A\u80FD\u4ECE\u56FE\u7247\u4E2D\u8BC6\u522B\u51FA\u4EFB\u4F55\u8BD5\u5377\u5185\u5BB9\uFF0C\u8BF7\u786E\u4FDD\u56FE\u7247\u6E05\u6670\u4E14\u5305\u542B\u8BD5\u5377\u5185\u5BB9\u3002");
  }
  return combined.length > MAX_ANALYSIS_TEXT_LENGTH ? combined.slice(0, MAX_ANALYSIS_TEXT_LENGTH) : combined;
}
async function gradeWithDeepSeek(recognizedText, env) {
  const prompt = [
    "\u4F60\u662F\u4E00\u4F4D\u7ECF\u9A8C\u4E30\u5BCC\u3001\u4E25\u8C28\u8D1F\u8D23\u7684\u6559\u5E08\uFF0C\u6B63\u5728\u6279\u6539\u5B66\u751F\u7684\u8BD5\u5377\u3002",
    "\u8BF7\u6839\u636E\u4EE5\u4E0B\u8BC6\u522B\u5230\u7684\u8BD5\u5377\u5185\u5BB9\uFF08\u5305\u542B\u9898\u76EE\u548C\u5B66\u751F\u7B54\u6848\uFF09\uFF0C\u9010\u9898\u8FDB\u884C\u6279\u6539\u3002",
    "",
    "\u6279\u6539\u8981\u6C42\uFF1A",
    "1. \u4ED4\u7EC6\u9605\u8BFB\u6BCF\u9053\u9898\u7684\u9898\u76EE\u5185\u5BB9",
    "2. \u6839\u636E\u9898\u76EE\u5185\u5BB9\u5224\u65AD\u6B63\u786E\u7B54\u6848",
    "3. \u5C06\u5B66\u751F\u7B54\u6848\u4E0E\u6B63\u786E\u7B54\u6848\u8FDB\u884C\u5BF9\u6BD4",
    "4. \u5224\u65AD\u5B66\u751F\u7B54\u6848\u662F\u5426\u6B63\u786E\uFF1A",
    "   - \u5B8C\u5168\u6B63\u786E\uFF1A\u5F97\u5206\u7387100%",
    "   - \u57FA\u672C\u6B63\u786E\u4F46\u6709\u5C0F\u7684\u8BA1\u7B97\u9519\u8BEF/\u62FC\u5199\u9519\u8BEF\uFF1A\u5F97\u5206\u738760-80%",
    "   - \u65B9\u6CD5\u6B63\u786E\u4F46\u7ED3\u679C\u9519\u8BEF\uFF1A\u5F97\u5206\u738740-60%",
    "   - \u5B8C\u5168\u9519\u8BEF\u6216\u672A\u4F5C\u7B54\uFF1A\u5F97\u5206\u73870%",
    "5. \u5BF9\u4E8E\u89E3\u7B54\u9898/\u8BA1\u7B97\u9898\uFF0C\u8981\u8003\u8651\u89E3\u9898\u8FC7\u7A0B\u662F\u5426\u5B8C\u6574\u3001\u65B9\u6CD5\u662F\u5426\u6B63\u786E",
    "6. \u5BF9\u4E8E\u9009\u62E9\u9898/\u5224\u65AD\u9898\uFF0C\u53EA\u6709\u5B8C\u5168\u9009\u5BF9\u624D\u7ED9100%\uFF0C\u9009\u9519\u7ED90%",
    "7. \u5BF9\u4E8E\u586B\u7A7A\u9898\uFF0C\u7B54\u6848\u5B8C\u5168\u4E00\u81F4\u7ED9100%\uFF0C\u90E8\u5206\u6B63\u786E\u7ED950%",
    "",
    "\u8F93\u51FA JSON \u5BF9\u8C61\uFF0C\u5305\u542B\u4EE5\u4E0B\u5B57\u6BB5\uFF1A",
    "- summary: \u6279\u6539\u603B\u7ED3",
    "- subject: \u5B66\u79D1",
    "- grade: \u5E74\u7EA7",
    "- questionCount: \u9898\u76EE\u603B\u6570",
    "- knowledgeCoverage: \u77E5\u8BC6\u70B9\u8986\u76D6\uFF08\u6570\u7EC4\uFF0C\u6BCF\u9879\u542Bname\u548Ccount\uFF09",
    "- difficultyDistribution: \u96BE\u5EA6\u5206\u5E03\uFF08easy/medium/hard\uFF09",
    "- questionTypes: \u9898\u578B\u5206\u5E03\uFF08\u6570\u7EC4\uFF0C\u6BCF\u9879\u542Btype\u548Ccount\uFF09",
    "- weakPoints: \u8584\u5F31\u77E5\u8BC6\u70B9\u5217\u8868",
    "- lectureSuggestions: \u8BB2\u8BC4\u5EFA\u8BAE",
    "- questions: \u9898\u76EE\u6570\u7EC4\uFF0C\u6BCF\u9879\u5FC5\u987B\u5305\u542B\uFF1A",
    "  - type: \u9898\u578B",
    "  - knowledgePoints: \u77E5\u8BC6\u70B9\u6570\u7EC4",
    "  - difficulty: \u7B80\u5355/\u4E2D\u7B49/\u56F0\u96BE",
    "  - score: \u6EE1\u5206",
    "  - scoreRate: \u5F97\u5206\u7387\uFF080-100\u7684\u6574\u6570\uFF0C\u57FA\u4E8E\u7B54\u6848\u6B63\u786E\u6027\u7ED9\u51FA\uFF09",
    "  - question: \u9898\u76EE\u5185\u5BB9",
    "  - answer: \u6B63\u786E\u7B54\u6848",
    "  - studentAnswer: \u5B66\u751F\u5199\u7684\u7B54\u6848",
    "  - isCorrect: true/false\uFF08\u662F\u5426\u5B8C\u5168\u6B63\u786E\uFF09",
    "  - feedback: \u6279\u6539\u8BC4\u8BED\uFF08\u8BF4\u660E\u6263\u5206\u539F\u56E0\uFF09",
    "",
    "\u4E0D\u8981\u8F93\u51FA Markdown\uFF0C\u76F4\u63A5\u8F93\u51FA JSON \u5BF9\u8C61\u3002",
    "",
    "\u8BC6\u522B\u5230\u7684\u8BD5\u5377\u5185\u5BB9\uFF1A",
    recognizedText.slice(0, MAX_ANALYSIS_TEXT_LENGTH)
  ].join("\n");
  const response = await fetch("https://api.deepseek.com/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.DEEPSEEK_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: env.DEEPSEEK_MODEL || "deepseek-chat",
      temperature: 0.2,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: "\u4F60\u53EA\u8F93\u51FA\u7B26\u5408\u8981\u6C42\u7684 JSON \u5BF9\u8C61\u3002\u6279\u6539\u8981\u4E25\u683C\u3001\u5BA2\u89C2\u3001\u51C6\u786E\uFF0C\u57FA\u4E8E\u5B66\u751F\u5B9E\u9645\u4F5C\u7B54\u5185\u5BB9\u8BC4\u5206\u3002"
        },
        { role: "user", content: prompt }
      ]
    })
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(`DeepSeek \u6279\u6539\u5931\u8D25\uFF1A${payload?.error?.message || response.statusText}`);
  }
  const content = payload?.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error("DeepSeek \u672A\u8FD4\u56DE\u6709\u6548\u6279\u6539\u7ED3\u679C\u3002");
  }
  return normalizeAnalysis(parseJsonObject(content));
}
async function updateQuestionScores(env, user, questions) {
  const recentQuestions = await env.DB.prepare(
    "SELECT id FROM questions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?"
  ).bind(user.id, questions.length).all();
  const existingIds = (recentQuestions.results || []).map((r) => r.id);
  const now = (/* @__PURE__ */ new Date()).toISOString();
  for (let i = 0; i < questions.length && i < existingIds.length; i++) {
    const q = questions[i];
    const questionId = existingIds[i];
    await env.DB.prepare(
      "UPDATE questions SET score_rate = ?, answer = ? WHERE id = ? AND user_id = ?"
    ).bind(
      Math.round(Number(q.scoreRate) || 0),
      String(q.answer || q.studentAnswer || q.analysis || "").slice(0, 2e3),
      questionId,
      user.id
    ).run();
  }
}
async function buildDefaultAnalysisText(files, textParts, env) {
  const parts = [...textParts];
  for (const file of files) {
    if (file.type.startsWith("image/")) {
      const imageBase64 = await fileToBase64(file);
      parts.push(await recognizeWithBaidu(imageBase64, env));
    }
  }
  const combined = parts.join("\n\n---\n\n").trim();
  if (!combined) {
    throw new HttpError(400, "\u9ED8\u8BA4\u65B9\u5F0F\u9700\u8981\u56FE\u7247 OCR \u5185\u5BB9\u6216\u53EF\u63D0\u53D6\u6587\u5B57\u7684 PDF\u3002\u626B\u63CF\u7248 PDF \u8BF7\u5148\u8F6C\u6210\u56FE\u7247\u4E0A\u4F20\u3002");
  }
  if (combined.length > MAX_ANALYSIS_TEXT_LENGTH) {
    return combined.slice(0, MAX_ANALYSIS_TEXT_LENGTH);
  }
  return combined;
}
async function extractTextWithGPTVision(files, textParts, env) {
  const parts = [...textParts];
  for (const file of files) {
    if (!file.type.startsWith("image/")) continue;
    const imageBase64 = await fileToBase64(file);
    const mimeType = file.type || "image/jpeg";
    const dataUrl = `data:${mimeType};base64,${imageBase64}`;
    const response = await fetch(`${(env.GPT_API_BASE || "https://geekspace.cloud/v1").replace(/\/+$/, "")}/chat/completions`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.GEEKSPACE_API_KEY || env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: env.OPENAI_MODEL || "gpt-5.5",
        temperature: 0.1,
        messages: [
          {
            role: "system",
            content: "\u4F60\u53EA\u8F93\u51FA\u8BC6\u522B\u51FA\u7684\u6587\u5B57\u5185\u5BB9\uFF0C\u4E0D\u8981\u8FDB\u884C\u4EFB\u4F55\u5206\u6790\u3001\u8BC4\u4EF7\u6216\u8865\u5145\u3002"
          },
          {
            role: "user",
            content: [
              { type: "text", text: "\u8BF7\u8BC6\u522B\u5E76\u63D0\u53D6\u8FD9\u5F20\u8BD5\u5377\u56FE\u7247\u4E2D\u7684\u6240\u6709\u6587\u5B57\u5185\u5BB9\uFF0C\u4FDD\u6301\u539F\u6709\u7684\u683C\u5F0F\u548C\u6392\u7248\u7ED3\u6784\uFF0C\u5305\u62EC\u9898\u76EE\u3001\u9009\u9879\u3001\u5206\u503C\u3001\u516C\u5F0F\u7B49\u3002\u76F4\u63A5\u8F93\u51FA\u6587\u5B57\uFF0C\u4E0D\u8981\u52A0\u4EFB\u4F55\u8BF4\u660E\u3002" },
              { type: "image_url", image_url: { url: dataUrl } }
            ]
          }
        ]
      })
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok) {
      const errMsg = payload?.error?.message || response.statusText;
      throw new Error(`GPT \u56FE\u7247\u8BC6\u522B\u5931\u8D25\uFF1A${errMsg.slice(0, 100)}`);
    }
    const text = payload?.choices?.[0]?.message?.content;
    if (text) {
      parts.push(text.trim());
    }
  }
  const combined = parts.join("\n\n---\n\n").trim();
  if (!combined) {
    throw new Error("\u591A\u6A21\u6001\u65B9\u5F0F\u9700\u8981\u4E0A\u4F20\u8BD5\u5377\u56FE\u7247\u6216\u53EF\u63D0\u53D6\u6587\u5B57\u7684 PDF\u3002");
  }
  return combined.length > MAX_ANALYSIS_TEXT_LENGTH ? combined.slice(0, MAX_ANALYSIS_TEXT_LENGTH) : combined;
}
async function handleListQuestions(env, corsHeaders, user) {
  const rows = await env.DB.prepare(
    [
      "SELECT questions.id, questions.type, questions.knowledge_points, questions.difficulty,",
      "questions.score, questions.score_rate, questions.question, questions.answer,",
      "papers.title AS paper_title, papers.created_at AS paper_created_at",
      "FROM questions",
      "LEFT JOIN papers ON papers.id = questions.paper_id",
      "WHERE questions.user_id = ?",
      "ORDER BY questions.created_at DESC",
      "LIMIT 1000"
    ].join(" ")
  ).bind(user.id).all();
  const questions = (rows.results || []).map((row) => ({
    id: row.id,
    type: row.type,
    knowledgePoints: safeJsonArray(row.knowledge_points),
    difficulty: row.difficulty,
    score: row.score,
    scoreRate: row.score_rate,
    question: row.question,
    answer: row.answer || "",
    paperTitle: row.paper_title || "",
    paperCreatedAt: row.paper_created_at || ""
  }));
  return json({ questions }, 200, corsHeaders);
}
async function handleClearQuestions(env, corsHeaders, user) {
  await env.DB.prepare("DELETE FROM paper_files WHERE paper_id IN (SELECT id FROM papers WHERE user_id = ?)").bind(user.id).run();
  await env.DB.prepare("DELETE FROM questions WHERE user_id = ?").bind(user.id).run();
  await env.DB.prepare("DELETE FROM papers WHERE user_id = ?").bind(user.id).run();
  await logUsage(env, user.id, "clear_questions", null, "user cleared question database");
  return json({ ok: true }, 200, corsHeaders);
}
async function handleListStudents(env, corsHeaders, user) {
  const rows = await env.DB.prepare(
    [
      "SELECT id, student_no, name, class_name, avg_rate, total_questions, kp_data, created_at, updated_at",
      "FROM students",
      "WHERE user_id = ?",
      "ORDER BY updated_at DESC, created_at DESC",
      "LIMIT 1000"
    ].join(" ")
  ).bind(user.id).all();
  const students = (rows.results || []).map((row) => ({
    dbId: row.id,
    id: row.student_no,
    name: row.name,
    class: row.class_name,
    avgRate: row.avg_rate,
    totalQuestions: row.total_questions,
    kpData: safeJsonObject(row.kp_data),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  }));
  return json({ students }, 200, corsHeaders);
}
async function handleCreateStudent(request, env, corsHeaders, user) {
  const payload = await request.json().catch(() => null);
  const studentNo = normalizeStudentText(payload?.id, 32);
  const name = normalizeStudentText(payload?.name, 40);
  const className = normalizeStudentText(payload?.class, 60);
  const avgRate = clamp(numberOrDefault(payload?.avgRate, 60), 0, 100);
  const totalQuestions = Math.max(0, Math.round(numberOrDefault(payload?.totalQuestions, 0)));
  const kpData = normalizeKpData(payload?.kpData, avgRate);
  if (!name) throw new HttpError(400, "\u8BF7\u8F93\u5165\u5B66\u751F\u59D3\u540D\u3002");
  if (!studentNo) throw new HttpError(400, "\u8BF7\u8F93\u5165\u5B66\u53F7\u3002");
  if (!className) throw new HttpError(400, "\u8BF7\u9009\u62E9\u6216\u8F93\u5165\u73ED\u7EA7\u3002");
  const existing = await env.DB.prepare("SELECT id FROM students WHERE user_id = ? AND student_no = ?").bind(user.id, studentNo).first();
  if (existing) {
    throw new HttpError(409, `\u5B66\u53F7 ${studentNo} \u5DF2\u5B58\u5728\u3002`);
  }
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const dbId = crypto.randomUUID();
  await env.DB.prepare(
    [
      "INSERT INTO students",
      "(id, user_id, student_no, name, class_name, avg_rate, total_questions, kp_data, created_at, updated_at)",
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ].join(" ")
  ).bind(dbId, user.id, studentNo, name, className, avgRate, totalQuestions, JSON.stringify(kpData), now, now).run();
  await logUsage(env, user.id, "create_student", null, JSON.stringify({ studentNo, className }));
  return json(
    {
      student: {
        dbId,
        id: studentNo,
        name,
        class: className,
        avgRate,
        totalQuestions,
        kpData,
        createdAt: now,
        updatedAt: now
      }
    },
    200,
    corsHeaders
  );
}
async function handleDeleteStudent(request, env, corsHeaders, user) {
  const payload = await request.json().catch(() => null);
  const dbId = typeof (payload == null ? void 0 : payload.dbId) === "string" ? payload.dbId.trim() : "";
  if (!dbId) throw new HttpError(400, "\u7F3A\u5C11\u5B66\u751FID\u3002");
  const result = await env.DB.prepare("DELETE FROM students WHERE id = ? AND user_id = ?").bind(dbId, user.id).run();
  if (result.meta.changes === 0) {
    throw new HttpError(404, "\u672A\u627E\u5230\u8BE5\u5B66\u751F\uFF0C\u53EF\u80FD\u5DF2\u88AB\u5220\u9664\u3002");
  }
  await logUsage(env, user.id, "delete_student", null, JSON.stringify({ dbId }));
  return json({ ok: true }, 200, corsHeaders);
}
async function handleUpdateStudent(request, env, corsHeaders, user) {
  const payload = await request.json().catch(() => null);
  const dbId = typeof (payload == null ? void 0 : payload.dbId) === "string" ? payload.dbId.trim() : "";
  if (!dbId) throw new HttpError(400, "\u7F3A\u5C11\u5B66\u751FID\u3002");
  const name = normalizeStudentText(payload == null ? void 0 : payload.name, 40);
  const className = normalizeStudentText(payload == null ? void 0 : payload.class, 60);
  const avgRate = clamp(numberOrDefault(payload == null ? void 0 : payload.avgRate, 60), 0, 100);
  const totalQuestions = Math.max(0, Math.round(numberOrDefault(payload == null ? void 0 : payload.totalQuestions, 0)));
  const kpData = normalizeKpData(payload == null ? void 0 : payload.kpData, avgRate);
  if (!name) throw new HttpError(400, "\u8BF7\u8F93\u5165\u5B66\u751F\u59D3\u540D\u3002");
  if (!className) throw new HttpError(400, "\u8BF7\u9009\u62E9\u6216\u8F93\u5165\u73ED\u7EA7\u3002");
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const result = await env.DB.prepare(
    [
      "UPDATE students",
      "SET name = ?, class_name = ?, avg_rate = ?, total_questions = ?, kp_data = ?, updated_at = ?",
      "WHERE id = ? AND user_id = ?"
    ].join(" ")
  ).bind(name, className, avgRate, totalQuestions, JSON.stringify(kpData), now, dbId, user.id).run();
  if (result.meta.changes === 0) {
    throw new HttpError(404, "\u672A\u627E\u5230\u8BE5\u5B66\u751F\uFF0C\u53EF\u80FD\u5DF2\u88AB\u5220\u9664\u3002");
  }
  await logUsage(env, user.id, "update_student", null, JSON.stringify({ dbId, studentNo: payload == null ? void 0 : payload.id }));
  return json({
    ok: true,
    student: {
      dbId,
      id: (payload == null ? void 0 : payload.id) || "",
      name,
      class: className,
      avgRate,
      totalQuestions,
      kpData,
      updatedAt: now
    }
  }, 200, corsHeaders);
}
async function savePaperResult(env, user, input) {
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const paperId = crypto.randomUUID();
  const questions = normalizeQuestions(input.result.questions || []);
  await env.DB.prepare(
    [
      "INSERT INTO papers",
      "(id, user_id, title, mode, source_text_preview, summary, subject, grade, question_count, created_at, updated_at)",
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ].join(" ")
  ).bind(
    paperId,
    user.id,
    input.title,
    input.mode,
    input.result.originalTextPreview || input.textParts.join("\n\n").slice(0, 1200),
    input.result.summary,
    input.result.subject || "",
    input.result.grade || "",
    questions.length,
    now,
    now
  ).run();
  for (const file of input.files) {
    await env.DB.prepare(
      "INSERT INTO paper_files (id, paper_id, file_name, mime_type, file_size, extracted_text_preview, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(crypto.randomUUID(), paperId, file.name || "upload", file.type || "application/octet-stream", file.size, "", now).run();
  }
  for (const question of questions) {
    await env.DB.prepare(
      [
        "INSERT INTO questions",
        "(id, paper_id, user_id, type, knowledge_points, difficulty, score, score_rate, question, answer, created_at)",
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
      ].join(" ")
    ).bind(
      crypto.randomUUID(),
      paperId,
      user.id,
      question.type,
      JSON.stringify(question.knowledgePoints),
      question.difficulty,
      question.score,
      question.scoreRate,
      question.question,
      question.answer,
      now
    ).run();
  }
  await logUsage(env, user.id, "analyze_paper", input.provider, JSON.stringify({ mode: input.mode, files: input.files.length }));
  return {
    id: paperId,
    title: input.title,
    mode: input.mode,
    createdAt: now,
    questionCount: questions.length
  };
}
async function recognizeWithBaidu(imageBase64, env) {
  const mode = env.BAIDU_OCR_MODE || "auto";
  if (mode === "formula") {
    return recognizeFormulaWithBaidu(imageBase64, env);
  }
  if (mode === "auto") {
    try {
      const formulaText = await recognizeFormulaWithBaidu(imageBase64, env);
      if (looksLikeUsefulMathText(formulaText)) return formulaText;
    } catch {
    }
  }
  return recognizeAccurateBasicWithBaidu(imageBase64, env);
}
async function recognizeAccurateBasicWithBaidu(imageBase64, env) {
  const accessToken = await getBaiduAccessToken(env);
  const body = new URLSearchParams({
    image: imageBase64,
    language_type: "CHN_ENG",
    detect_direction: "true",
    paragraph: "true"
  });
  const response = await fetch(`https://aip.baidubce.com/rest/2.0/ocr/v1/accurate_basic?access_token=${accessToken}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const payload = await response.json();
  if (!response.ok || payload.error_msg) {
    throw new Error(`\u767E\u5EA6 OCR \u8BC6\u522B\u5931\u8D25\uFF1A${payload.error_msg || response.statusText}`);
  }
  const text = payload.words_result?.map((item) => item.words).join("\n").trim() ?? "";
  if (!text) {
    throw new Error("OCR \u672A\u8BC6\u522B\u5230\u6709\u6548\u6587\u5B57\uFF0C\u8BF7\u6362\u4E00\u5F20\u66F4\u6E05\u6670\u7684\u8BD5\u5377\u56FE\u7247\u3002");
  }
  return text;
}
async function recognizeFormulaWithBaidu(imageBase64, env) {
  const accessToken = await getBaiduAccessToken(env);
  const response = await fetch(`https://aip.baidubce.com/rest/2.0/ocr/v1/formula?access_token=${accessToken}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ image: imageBase64 })
  });
  const payload = await response.json();
  if (!response.ok || payload.error_msg) {
    throw new Error(`\u767E\u5EA6\u516C\u5F0F OCR \u8BC6\u522B\u5931\u8D25\uFF1A${payload.error_msg || response.statusText}`);
  }
  const items = payload.formula_result ?? payload.words_result ?? [];
  const text = items.map((item) => item.formula || item.words || "").filter(Boolean).join("\n").trim();
  if (!text) {
    throw new Error("\u516C\u5F0F OCR \u672A\u8BC6\u522B\u5230\u6709\u6548\u6587\u5B57\u3002");
  }
  return text;
}
async function getBaiduAccessToken(env) {
  const response = await fetch("https://aip.baidubce.com/oauth/2.0/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      client_id: env.BAIDU_OCR_API_KEY || "",
      client_secret: env.BAIDU_OCR_SECRET_KEY || ""
    })
  });
  const payload = await response.json();
  if (!response.ok || !payload.access_token) {
    throw new Error(`\u767E\u5EA6 access_token \u83B7\u53D6\u5931\u8D25\uFF1A${payload.error_description || response.statusText}`);
  }
  return payload.access_token;
}
async function analyzeWithDeepSeek(ocrText, env) {
  const prompt = [
    "\u4F60\u662F\u9762\u5411\u4E2D\u5C0F\u5B66\u6559\u5E08\u7684\u8BD5\u5377\u5206\u6790\u52A9\u624B\u3002",
    "\u8BF7\u6839\u636E\u8BD5\u5377\u6587\u672C\u8BC6\u522B\u9898\u76EE\u5E76\u5206\u6790\u8BD5\u5377\uFF0C\u4E25\u683C\u8F93\u51FA JSON \u5BF9\u8C61\uFF0C\u4E0D\u8981\u8F93\u51FA Markdown\u3002",
    "JSON \u5B57\u6BB5\u5FC5\u987B\u5305\u542B summary, subject, grade, questionCount, knowledgeCoverage, difficultyDistribution, questionTypes, weakPoints, lectureSuggestions, questions\u3002",
    "questions \u662F\u9898\u76EE\u6570\u7EC4\uFF0C\u6BCF\u9879\u5305\u542B type, knowledgePoints, difficulty, score, question, answer\u3002",
    "difficulty \u53EA\u80FD\u4F7F\u7528 \u7B80\u5355\u3001\u4E2D\u7B49\u3001\u56F0\u96BE\uFF1Btype \u4F18\u5148\u4F7F\u7528 \u9009\u62E9\u9898\u3001\u586B\u7A7A\u9898\u3001\u89E3\u7B54\u9898\u3001\u5224\u65AD\u9898\u3001\u5176\u4ED6\u3002",
    "\u4E0D\u8981\u8F93\u51FA\u6216\u4F30\u8BA1\u5F97\u5206\u7387\uFF0C\u5F97\u5206\u7387\u53EA\u5C5E\u4E8E\u9605\u5377\u7ED3\u679C\uFF0C\u4E0D\u5C5E\u4E8E\u8BD5\u5377\u7ED3\u6784\u5206\u6790\u3002",
    "\u5982\u679C\u9898\u76EE\u4FE1\u606F\u4E0D\u5B8C\u6574\uFF0C\u8BF7\u57FA\u4E8E\u53EF\u89C1\u5185\u5BB9\u505A\u6982\u62EC\u6027\u5206\u6790\uFF1B\u4E0D\u8981\u8BC4\u4EF7 OCR \u8D28\u91CF\u6216\u8BC6\u522B\u8FC7\u7A0B\u3002",
    "",
    "\u8BD5\u5377\u6587\u672C\uFF1A",
    ocrText.slice(0, MAX_ANALYSIS_TEXT_LENGTH)
  ].join("\n");
  const response = await fetch("https://api.deepseek.com/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.DEEPSEEK_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: env.DEEPSEEK_MODEL || "deepseek-chat",
      temperature: 0.2,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: "\u4F60\u53EA\u8F93\u51FA\u7B26\u5408\u8981\u6C42\u7684 JSON \u5BF9\u8C61\uFF0C\u5B57\u6BB5\u7F3A\u5931\u65F6\u4F7F\u7528\u5408\u7406\u9ED8\u8BA4\u503C\u3002"
        },
        { role: "user", content: prompt }
      ]
    })
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(`DeepSeek \u5206\u6790\u5931\u8D25\uFF1A${payload?.error?.message || response.statusText}`);
  }
  const content = payload?.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error("DeepSeek \u672A\u8FD4\u56DE\u6709\u6548\u5206\u6790\u7ED3\u679C\u3002");
  }
  return normalizeAnalysis(parseJsonObject(content));
}
function parseJsonObject(content) {
  try {
    return JSON.parse(content);
  } catch {
    const match = content.match(/\{[\s\S]*\}/);
    if (!match) throw new Error("\u6A21\u578B\u8FD4\u56DE\u5185\u5BB9\u4E0D\u662F\u6709\u6548 JSON\u3002");
    return JSON.parse(match[0]);
  }
}
function normalizeAnalysis(value) {
  const questions = normalizeQuestions(Array.isArray(value.questions) ? value.questions : []);
  return {
    summary: value.summary || "\u5DF2\u5B8C\u6210\u8BD5\u5377\u7ED3\u6784\u4E0E\u8BB2\u8BC4\u91CD\u70B9\u5206\u6790\u3002",
    subject: value.subject || "",
    grade: value.grade || "",
    questionCount: numberOrUndefined(value.questionCount) || questions.length,
    knowledgeCoverage: Array.isArray(value.knowledgeCoverage) ? value.knowledgeCoverage.slice(0, 12) : [],
    difficultyDistribution: {
      easy: Number(value.difficultyDistribution?.easy ?? 0),
      medium: Number(value.difficultyDistribution?.medium ?? 0),
      hard: Number(value.difficultyDistribution?.hard ?? 0)
    },
    questionTypes: Array.isArray(value.questionTypes) ? value.questionTypes.slice(0, 12) : [],
    weakPoints: Array.isArray(value.weakPoints) ? value.weakPoints.slice(0, 8) : [],
    lectureSuggestions: Array.isArray(value.lectureSuggestions) ? value.lectureSuggestions.slice(0, 8) : [],
    questions,
    originalTextPreview: ""
  };
}
function normalizeQuestions(questions) {
  return questions.slice(0, 200).map((question, index) => {
    const score = numberOrDefault(question.score ?? question.fullScore, 5);
    return {
      id: question.id || `${Date.now()}-${index}`,
      type: normalizeQuestionType(question.type),
      knowledgePoints: normalizeKnowledgePoints(question.knowledgePoints),
      difficulty: normalizeDifficulty(question.difficulty),
      score,
      fullScore: score,
      scoreRate: clamp(numberOrDefault(question.scoreRate ?? question.rate, 60), 0, 100),
      rate: clamp(numberOrDefault(question.scoreRate ?? question.rate, 60), 0, 100),
      question: String(question.question || question.content || question.text || "\u672A\u8BC6\u522B\u9898\u76EE").trim(),
      content: String(question.content || question.question || question.text || "").trim(),
      text: String(question.text || question.question || question.content || "").trim(),
      answer: String(question.answer || question.analysis || "").trim(),
      analysis: String(question.analysis || question.answer || "").trim(),
      studentAnswer: String(question.studentAnswer || "").trim(),
      isCorrect: question.isCorrect === true,
      feedback: String(question.feedback || "").trim()
    };
  });
}
async function withSessionCookie(request, env, corsHeaders, user) {
  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const now = /* @__PURE__ */ new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_SECONDS * 1e3).toISOString();
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ? OR expires_at <= ?").bind(user.id, now.toISOString()).run();
  await env.DB.prepare("INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)").bind(crypto.randomUUID(), user.id, tokenHash, now.toISOString(), expiresAt).run();
  return json(
    { user },
    200,
    {
      ...corsHeaders,
      "Set-Cookie": makeSessionCookie(request, token)
    }
  );
}
async function getCurrentUser(request, env) {
  assertDatabaseConfigured(env);
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    [
      "SELECT users.id, users.email, users.name, users.created_at",
      "FROM sessions",
      "JOIN users ON users.id = sessions.user_id",
      "WHERE sessions.token_hash = ? AND sessions.expires_at > ?",
      "LIMIT 1"
    ].join(" ")
  ).bind(tokenHash, (/* @__PURE__ */ new Date()).toISOString()).first();
  if (!row) return null;
  return { id: row.id, email: row.email, name: row.name, createdAt: row.created_at };
}
async function requireUser(request, env) {
  const user = await getCurrentUser(request, env);
  if (!user) throw new AuthError("\u8BF7\u5148\u767B\u5F55\u540E\u518D\u4F7F\u7528\u8BE5\u529F\u80FD\u3002");
  return user;
}
async function getUserById(env, userId) {
  const row = await env.DB.prepare("SELECT id, email, name, created_at FROM users WHERE id = ?").bind(userId).first();
  if (!row) return null;
  return { id: row.id, email: row.email, name: row.name, createdAt: row.created_at };
}
async function logUsage(env, userId, eventType, provider, detail) {
  await env.DB.prepare(
    "INSERT INTO usage_events (id, user_id, event_type, provider, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(crypto.randomUUID(), userId, eventType, provider, detail, (/* @__PURE__ */ new Date()).toISOString()).run();
}
function validateUploadedFile(file) {
  if (file.size > MAX_FILE_SIZE) {
    throw new HttpError(400, `\u6587\u4EF6 ${file.name || ""} \u8D85\u8FC7 4MB\uFF0C\u8BF7\u538B\u7F29\u540E\u91CD\u8BD5\u3002`);
  }
  const supported = file.type.startsWith("image/") || file.type === "application/pdf";
  if (!supported) {
    throw new HttpError(400, "\u4EC5\u652F\u6301 JPG\u3001PNG\u3001WEBP \u56FE\u7247\u6216\u53EF\u63D0\u53D6\u6587\u5B57\u7684 PDF\u3002");
  }
}
function isUploadedFile(value) {
  return typeof value === "object" && value !== null && "arrayBuffer" in value && "size" in value && "type" in value;
}
function inferPaperTitle(files) {
  if (files.length === 0) return `\u8BD5\u5377\u5206\u6790 ${(/* @__PURE__ */ new Date()).toLocaleDateString("zh-CN")}`;
  if (files.length === 1) return files[0].name || "\u8BD5\u5377\u5206\u6790";
  return `${files[0].name || "\u8BD5\u5377"} \u7B49 ${files.length} \u4E2A\u6587\u4EF6`;
}
function safeJsonArray(value) {
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed.map(String);
  } catch {
  }
  return value ? [value] : ["\u672A\u5206\u7C7B"];
}
function safeJsonObject(value) {
  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const result = {};
      for (const [key, rawValue] of Object.entries(parsed)) {
        const normalizedKey = String(key).trim();
        if (!normalizedKey) continue;
        result[normalizedKey] = clamp(numberOrDefault(rawValue, 0), 0, 100);
      }
      return result;
    }
  } catch {
  }
  return {};
}
function normalizeStudentText(value, maxLength) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}
function normalizeKpData(value, avgRate) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const result = {};
  for (const [key, rawValue] of Object.entries(value)) {
    const normalizedKey = key.trim().slice(0, 60);
    if (!normalizedKey) continue;
    result[normalizedKey] = clamp(numberOrDefault(rawValue, avgRate), 0, 100);
  }
  return result;
}
function normalizeQuestionType(type) {
  const text = String(type || "").trim();
  if (["\u9009\u62E9\u9898", "\u586B\u7A7A\u9898", "\u89E3\u7B54\u9898", "\u5224\u65AD\u9898", "\u5176\u4ED6"].includes(text)) return text;
  return "\u5176\u4ED6";
}
function normalizeDifficulty(difficulty) {
  const text = String(difficulty || "").trim();
  if (["\u7B80\u5355", "\u4E2D\u7B49", "\u56F0\u96BE"].includes(text)) return text;
  if (["easy", "low"].includes(text.toLowerCase())) return "\u7B80\u5355";
  if (["hard", "high"].includes(text.toLowerCase())) return "\u56F0\u96BE";
  return "\u4E2D\u7B49";
}
function normalizeKnowledgePoints(value) {
  const list = Array.isArray(value) ? value : value ? [value] : ["\u672A\u5206\u7C7B"];
  const normalized = list.map((item) => String(item).trim()).filter(Boolean);
  return normalized.length > 0 ? normalized.slice(0, 8) : ["\u672A\u5206\u7C7B"];
}
function numberOrUndefined(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : void 0;
  }
  return void 0;
}
function numberOrDefault(value, fallback) {
  return numberOrUndefined(value) ?? fallback;
}
function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}
function looksLikeUsefulMathText(text) {
  const compact = text.replace(/\s/g, "");
  if (compact.length < 80) return false;
  return ["\\frac", "\\sqrt", "\\sin", "\\cos", "\\tan", "^", "_", "{", "}"].some((signal) => compact.includes(signal));
}
async function fileToBase64(file) {
  const buffer = await file.arrayBuffer();
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const chunkSize = 32768;
  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }
  return btoa(binary);
}
function assertDatabaseConfigured(env) {
  if (!env.DB) throw new Error("\u540E\u7AEF\u7F3A\u5C11 D1 \u6570\u636E\u5E93\u7ED1\u5B9A\uFF1ADB");
}
function assertBaiduConfigured(env) {
  assertKeys([
    ["BAIDU_OCR_API_KEY", env.BAIDU_OCR_API_KEY],
    ["BAIDU_OCR_SECRET_KEY", env.BAIDU_OCR_SECRET_KEY]
  ]);
}
function assertDeepSeekConfigured(env) {
  assertKeys([["DEEPSEEK_API_KEY", env.DEEPSEEK_API_KEY]]);
}
function assertOpenAiConfigured(env) {
  assertKeys([["GEEKSPACE_API_KEY \u6216 OPENAI_API_KEY", env.GEEKSPACE_API_KEY || env.OPENAI_API_KEY]]);
}
function assertKeys(entries) {
  const missing = entries.filter(([, value]) => !value).map(([key]) => key);
  if (missing.length > 0) {
    throw new Error(`\u540E\u7AEF\u7F3A\u5C11\u73AF\u5883\u53D8\u91CF\uFF1A${missing.join(", ")}`);
  }
}
function getCorsHeaders(env, request) {
  const origin = request.headers.get("Origin");
  const configuredOrigins = (env.ALLOWED_ORIGINS || env.ALLOWED_ORIGIN || "*").split(",").map((item) => item.trim()).filter(Boolean);
  const allowAny = configuredOrigins.includes("*");
  const allowOrigin = allowAny && origin ? origin : origin && configuredOrigins.includes(origin) ? origin : configuredOrigins[0] || "*";
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Credentials": "true",
    Vary: "Origin"
  };
}
function json(data, status, headers) {
  return Response.json(data, {
    status,
    headers: {
      ...headers,
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}
function getErrorMessage(error, fallback) {
  return error instanceof Error ? error.message : fallback;
}
class AuthError extends Error {
}
class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
  status;
}
function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}
function normalizeName(value, email) {
  const name = typeof value === "string" ? value.trim() : "";
  return name || email.split("@")[0] || "\u8001\u5E08";
}
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
async function hashPassword(password) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derivePasswordHash(password, saltBytes, PASSWORD_ITERATIONS);
  return {
    hash: bytesToBase64(hash),
    salt: bytesToBase64(saltBytes)
  };
}
async function verifyPassword(password, salt, expectedHash, iterations) {
  const saltBytes = base64ToBytes(salt);
  const hash = await derivePasswordHash(password, saltBytes, iterations || PASSWORD_ITERATIONS);
  return timingSafeEqual(bytesToBase64(hash), expectedHash);
}
async function derivePasswordHash(password, salt, iterations) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  return new Uint8Array(bits);
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return diff === 0;
}
function randomToken() {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}
async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
function makeSessionCookie(request, token) {
  const isHttps = new URL(request.url).protocol === "https:";
  const sameSite = isHttps ? "None" : "Lax";
  const secure = isHttps ? "; Secure" : "";
  return `${SESSION_COOKIE}=${token}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_SECONDS}; SameSite=${sameSite}${secure}`;
}
function clearSessionCookie(request) {
  const isHttps = new URL(request.url).protocol === "https:";
  const sameSite = isHttps ? "None" : "Lax";
  const secure = isHttps ? "; Secure" : "";
  return `${SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=${sameSite}${secure}`;
}
function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  return cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${name}=`))?.slice(name.length + 1) || "";
}
function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}
function bytesToBase64Url(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
export {
  index_default as default
};
