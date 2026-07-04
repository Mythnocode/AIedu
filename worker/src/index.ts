type Env = {
  DB: D1Database;
  BAIDU_OCR_API_KEY?: string;
  BAIDU_OCR_SECRET_KEY?: string;
  DEEPSEEK_API_KEY?: string;
  GEEKSPACE_API_KEY?: string;
  OPENAI_API_KEY?: string;
  GPT_API_BASE?: string;
  DEEPSEEK_MODEL?: string;
  OPENAI_MODEL?: string;
  ALLOWED_ORIGIN?: string;
  ALLOWED_ORIGINS?: string;
  BAIDU_OCR_MODE?: 'auto' | 'accurate_basic' | 'formula';
};

type AuthUser = {
  id: string;
  email: string;
  name: string;
  createdAt: string;
};

type Question = {
  id?: string | number;
  type?: string;
  knowledgePoints?: string[] | string;
  difficulty?: string;
  score?: number | string;
  fullScore?: number | string;
  scoreRate?: number | string;
  rate?: number | string;
  question?: string;
  content?: string;
  text?: string;
  answer?: string;
  analysis?: string;
  studentAnswer?: string;
  isCorrect?: boolean;
  feedback?: string;
};

type AnalysisResult = {
  summary: string;
  subject?: string;
  grade?: string;
  questionCount?: number;
  knowledgeCoverage: Array<{ name: string; count: number; importance?: 'low' | 'medium' | 'high' }>;
  difficultyDistribution: { easy: number; medium: number; hard: number };
  questionTypes: Array<{ type: string; count: number }>;
  weakPoints: string[];
  lectureSuggestions: string[];
  questions: Required<Question>[];
  originalTextPreview: string;
};

type StoredPaper = {
  id: string;
  title: string;
  mode: string;
  createdAt: string;
  questionCount: number;
};

type StudentPayload = {
  id?: unknown;
  name?: unknown;
  class?: unknown;
  avgRate?: unknown;
  totalQuestions?: unknown;
  kpData?: unknown;
};

const MAX_FILES = 6;
const MAX_FILE_SIZE = 4 * 1024 * 1024;
const MAX_TOTAL_FILE_SIZE = 8 * 1024 * 1024;
const MAX_ANALYSIS_TEXT_LENGTH = 18000;
const SESSION_COOKIE = 'exam_analyzer_session';
const SESSION_TTL_SECONDS = 60 * 60 * 24 * 7;
const PASSWORD_ITERATIONS = 100000;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const corsHeaders = getCorsHeaders(env, request);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    try {
      if (url.pathname === '/api/health' && request.method === 'GET') {
        return json({ ok: true }, 200, corsHeaders);
      }

      if (url.pathname === '/api/auth/register' && request.method === 'POST') {
        return await handleRegister(request, env, corsHeaders);
      }

      if (url.pathname === '/api/auth/login' && request.method === 'POST') {
        return await handleLogin(request, env, corsHeaders);
      }

      if (url.pathname === '/api/auth/logout' && request.method === 'POST') {
        return await handleLogout(request, env, corsHeaders);
      }

      if (url.pathname === '/api/auth/me' && request.method === 'GET') {
        const user = await getCurrentUser(request, env);
        return json({ user }, 200, corsHeaders);
      }

      if (url.pathname === '/api/auth/profile' && request.method === 'POST') {
        const user = await requireUser(request, env);
        return await handleUpdateProfile(request, env, corsHeaders, user);
      }

      if (url.pathname === '/api/papers/analyze' && request.method === 'POST') {
        const user = await requireUser(request, env);
        return await handleAnalyzePaper(request, env, corsHeaders, user);
      }

      if (url.pathname === '/api/papers/grade' && request.method === 'POST') {
        const user = await requireUser(request, env);
        return await handleGradePaper(request, env, corsHeaders, user);
      }

      if (url.pathname === '/api/essay/grade' && request.method === 'POST') {
        const user = await requireUser(request, env);
        return await handleEssayGrading(request, env, corsHeaders, user);
      }

      if (url.pathname === '/api/mental-math/ocr' && request.method === 'POST') {
        const user = await requireUser(request, env);
        return await handleMentalMathOcr(request, env, corsHeaders, user);
      }

      if (url.pathname === '/api/questions' && request.method === 'GET') {
        const user = await requireUser(request, env);
        return await handleListQuestions(env, corsHeaders, user);
      }

      if (url.pathname === '/api/questions/clear' && request.method === 'POST') {
        const user = await requireUser(request, env);
        return await handleClearQuestions(env, corsHeaders, user);
      }

      if (url.pathname === '/api/students' && request.method === 'GET') {
        const user = await requireUser(request, env);
        return await handleListStudents(env, corsHeaders, user);
      }

      if (url.pathname === '/api/students' && request.method === 'POST') {
        const user = await requireUser(request, env);
        return await handleCreateStudent(request, env, corsHeaders, user);
      }

      return json({ message: 'Not found' }, 404, corsHeaders);
    } catch (error) {
      if (error instanceof AuthError) {
        return json({ message: error.message }, 401, corsHeaders);
      }

      if (error instanceof HttpError) {
        return json({ message: error.message }, error.status, corsHeaders);
      }

      return json({ message: getErrorMessage(error, '服务暂时不可用，请稍后重试。') }, 500, corsHeaders);
    }
  },
};

async function handleRegister(request: Request, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  assertDatabaseConfigured(env);
  const payload = (await request.json().catch(() => null)) as { email?: unknown; password?: unknown; name?: unknown } | null;
  const email = normalizeEmail(payload?.email);
  const password = typeof payload?.password === 'string' ? payload.password : '';
  const name = normalizeName(payload?.name, email);

  if (!email || !isValidEmail(email)) {
    throw new HttpError(400, '请输入有效邮箱。');
  }

  if (password.length < 8) {
    throw new HttpError(400, '密码至少需要 8 位。');
  }

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first<{ id: string }>();
  if (existing) {
    throw new HttpError(409, '该邮箱已注册，请直接登录。');
  }

  const userId = crypto.randomUUID();
  const passwordRecord = await hashPassword(password);
  const now = new Date().toISOString();

  await env.DB.prepare(
    'INSERT INTO users (id, email, name, password_hash, password_salt, password_iterations, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  )
    .bind(userId, email, name, passwordRecord.hash, passwordRecord.salt, PASSWORD_ITERATIONS, now, now)
    .run();

  return withSessionCookie(request, env, corsHeaders, { id: userId, email, name, createdAt: now });
}

async function handleLogin(request: Request, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  assertDatabaseConfigured(env);
  const payload = (await request.json().catch(() => null)) as { email?: unknown; password?: unknown } | null;
  const email = normalizeEmail(payload?.email);
  const password = typeof payload?.password === 'string' ? payload.password : '';

  if (!email || !password) {
    throw new HttpError(400, '请输入邮箱和密码。');
  }

  const row = await env.DB.prepare(
    'SELECT id, email, name, password_hash, password_salt, password_iterations, created_at FROM users WHERE email = ?',
  )
    .bind(email)
    .first<{
      id: string;
      email: string;
      name: string;
      password_hash: string;
      password_salt: string;
      password_iterations: number;
      created_at: string;
    }>();

  if (!row || !(await verifyPassword(password, row.password_salt, row.password_hash, row.password_iterations))) {
    throw new HttpError(401, '邮箱或密码不正确。');
  }

  return withSessionCookie(request, env, corsHeaders, {
    id: row.id,
    email: row.email,
    name: row.name,
    createdAt: row.created_at,
  });
}

async function handleLogout(request: Request, env: Env, corsHeaders: HeadersInit): Promise<Response> {
  assertDatabaseConfigured(env);
  const token = getCookie(request, SESSION_COOKIE);
  if (token) {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256Hex(token)).run();
  }

  return json(
    { ok: true },
    200,
    {
      ...corsHeaders,
      'Set-Cookie': clearSessionCookie(request),
    },
  );
}

async function handleUpdateProfile(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit,
  user: AuthUser,
): Promise<Response> {
  const payload = (await request.json().catch(() => null)) as {
    name?: unknown;
    currentPassword?: unknown;
    newPassword?: unknown;
  } | null;

  const name = typeof payload?.name === 'string' ? payload.name.trim() : '';
  const currentPassword = typeof payload?.currentPassword === 'string' ? payload.currentPassword : '';
  const newPassword = typeof payload?.newPassword === 'string' ? payload.newPassword : '';
  const now = new Date().toISOString();

  if (name) {
    await env.DB.prepare('UPDATE users SET name = ?, updated_at = ? WHERE id = ?').bind(name, now, user.id).run();
  }

  if (newPassword) {
    if (newPassword.length < 8) {
      throw new HttpError(400, '新密码至少需要 8 位。');
    }

    const row = await env.DB.prepare(
      'SELECT password_hash, password_salt, password_iterations FROM users WHERE id = ?',
    )
      .bind(user.id)
      .first<{ password_hash: string; password_salt: string; password_iterations: number }>();

    if (!row || !(await verifyPassword(currentPassword, row.password_salt, row.password_hash, row.password_iterations))) {
      throw new HttpError(401, '当前密码不正确。');
    }

    const passwordRecord = await hashPassword(newPassword);
    await env.DB.prepare(
      'UPDATE users SET password_hash = ?, password_salt = ?, password_iterations = ?, updated_at = ? WHERE id = ?',
    )
      .bind(passwordRecord.hash, passwordRecord.salt, PASSWORD_ITERATIONS, now, user.id)
      .run();
  }

  const updated = await getUserById(env, user.id);
  return json({ user: updated }, 200, corsHeaders);
}

async function handleAnalyzePaper(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit,
  user: AuthUser,
): Promise<Response> {
  const formData = await request.formData();
  const mode = String(formData.get('mode') || 'default');
  const title = String(formData.get('title') || '').trim();
  const files: File[] = [];
  for (const entry of formData.getAll('files')) {
    if (isUploadedFile(entry)) files.push(entry);
  }
  const textParts = formData
    .getAll('texts')
    .filter((value): value is string => typeof value === 'string')
    .map((value) => value.trim())
    .filter(Boolean);

  if (mode !== 'default' && mode !== 'multimodal') {
    throw new HttpError(400, '分析方式不正确。');
  }

  if (files.length === 0 && textParts.length === 0) {
    throw new HttpError(400, '请先上传试卷文件。');
  }

  if (files.length > MAX_FILES) {
    throw new HttpError(400, `一次最多分析 ${MAX_FILES} 个文件。`);
  }

  const totalFileSize = files.reduce((sum, file) => sum + file.size, 0);
  if (totalFileSize > MAX_TOTAL_FILE_SIZE) {
    throw new HttpError(400, '本次待分析文件总大小超过 8MB，请减少页数或压缩后重试。');
  }

  for (const file of files) {
    validateUploadedFile(file);
  }

  let result: AnalysisResult;
  let provider: string;

  if (mode === 'default') {
    assertBaiduConfigured(env);
    assertDeepSeekConfigured(env);
    const combinedText = await buildDefaultAnalysisText(files, textParts, env);
    result = await analyzeWithDeepSeek(combinedText, env);
    result.originalTextPreview = combinedText.slice(0, 1200);
    provider = 'baidu-ocr+deepseek';
  } else {
    assertOpenAiConfigured(env);
    assertDeepSeekConfigured(env);
    const extractedText = await extractTextWithGPTVision(files, textParts, env);
    result = await analyzeWithDeepSeek(extractedText, env);
    result.originalTextPreview = extractedText.slice(0, 1200);
    provider = 'gpt-vision+deepseek';
  }

  const paper = await savePaperResult(env, user, {
    title: title || inferPaperTitle(files),
    mode,
    provider,
    files,
    textParts,
    result,
  });

  return json({ paper, result }, 200, corsHeaders);
}

/**
 * 试卷自动批改：使用 GPT Vision 识别试卷图片中的题目和手写答案，
 * 再用 DeepSeek 逐题评估答案正确性，返回真实批改结果。
 */
async function handleGradePaper(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit,
  user: AuthUser,
): Promise<Response> {
  const formData = await request.formData();
  const files: File[] = [];
  for (const entry of formData.getAll('files')) {
    if (isUploadedFile(entry)) files.push(entry);
  }

  if (files.length === 0) {
    throw new HttpError(400, '请先上传试卷图片再进行批改。');
  }

  if (files.length > MAX_FILES) {
    throw new HttpError(400, `一次最多批改 ${MAX_FILES} 张图片。`);
  }

  const totalFileSize = files.reduce((sum, file) => sum + file.size, 0);
  if (totalFileSize > MAX_TOTAL_FILE_SIZE) {
    throw new HttpError(400, '图片总大小超过 8MB，请减少页数或压缩后重试。');
  }

  for (const file of files) {
    validateUploadedFile(file);
  }

  assertOpenAiConfigured(env);
  assertDeepSeekConfigured(env);

  // 第一步：用 GPT Vision 识别试卷图片中的题目内容和学生作答
  const recognizedText = await extractPaperContentWithVision(files, env);

  // 第二步：用 DeepSeek 逐题批改
  const gradeResult = await gradeWithDeepSeek(recognizedText, env);

  // 更新数据库中题目的得分率
  await updateQuestionScores(env, user, gradeResult.questions);

  await logUsage(env, user.id, 'paper_grade', 'gpt-vision+deepseek', `Graded ${gradeResult.questions.length} questions`);

  return json({ result: gradeResult }, 200, corsHeaders);
}

/**
 * 作文批改：调用大模型 DeepSeek 对作文内容进行深度分析批改。
 * 从内容立意、结构布局、语言表达、创新亮点四个维度评分，
 * 给出基于实际内容的真实评价，杜绝"随便写就有分"的问题。
 */
async function handleEssayGrading(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit,
  user: AuthUser,
): Promise<Response> {
  const payload = (await request.json().catch(() => null)) as {
    title?: string;
    content?: string;
  } | null;

  const title = String(payload?.title || '').trim();
  const content = String(payload?.content || '').trim();

  if (content.length < 50) {
    throw new HttpError(400, '作文正文至少需要50字。');
  }

  if (content.length > 10000) {
    throw new HttpError(400, '作文正文过长，请控制在10000字以内。');
  }

  assertDeepSeekConfigured(env);

  const result = await gradeEssayWithDeepSeek(title, content, env);

  await logUsage(env, user.id, 'essay_grade', 'deepseek', JSON.stringify({ title: title.slice(0, 60), wordCount: content.length, totalScore: result.totalScore }));

  return json({ result }, 200, corsHeaders);
}

/**
 * 调用 DeepSeek 大模型对作文进行真实的深度批改
 */
async function gradeEssayWithDeepSeek(
  title: string,
  content: string,
  env: Env,
): Promise<{
  totalScore: number;
  grade: string;
  dimensions: Array<{
    name: string;
    max: number;
    score: number;
    feedback: string;
  }>;
  comment: string;
  strengths: string[];
  weaknesses: string[];
  suggestions: string[];
}> {
  const prompt = [
    '你是一位经验丰富、严谨负责的语文教师，正在批改学生的作文。',
    '请仔细阅读学生的作文全文，基于实际内容质量进行客观、公正的评分。',
    '评分必须严格依据作文的真实水平，不要刻意给高分或低分。',
    '',
    '评分维度和分值：',
    '1. 内容立意（满分30分）：评估主题是否明确、立意是否深刻、内容是否充实、是否有具体事例和真情实感',
    '2. 结构布局（满分20分）：评估文章结构是否完整、层次是否清晰、开头结尾是否呼应、段落安排是否合理、过渡是否自然',
    '3. 语言表达（满分30分）：评估语言是否通顺流畅、用词是否准确丰富、是否恰当运用修辞手法、句式是否多样、标点使用是否规范',
    '4. 创新亮点（满分20分）：评估是否有独特视角、是否有生动的细节描写、是否有创意和想象力、是否有个性化表达',
    '',
    '评分标准：',
    '- 内容空洞、主题不清、偏离题意的作文必须低分（总分40分以下）',
    '- 内容充实、主题明确、结构合理的作文给中等分数（60-75分）',
    '- 只有主题深刻、内容丰富、语言优美、有亮点的优秀作文才能给高分（80分以上）',
    '- 如果作文内容毫无逻辑、胡乱凑字数、与标题完全无关，总分应在30分以下',
    '- 如果作文内容基本通顺但平淡无奇，总分应在50-65分之间',
    '',
    '请严格输出 JSON 对象，不要输出 Markdown 格式。JSON 字段如下：',
    '{',
    '  "totalScore": 数字(总分0-100),',
    '  "dimensions": [',
    '    {"name":"内容立意","max":30,"score":数字,"feedback":"该维度的具体评价（必须引用作文中的实际内容来佐证）"},',
    '    {"name":"结构布局","max":20,"score":数字,"feedback":"该维度的具体评价"},',
    '    {"name":"语言表达","max":30,"score":数字,"feedback":"该维度的具体评价"},',
    '    {"name":"创新亮点","max":20,"score":数字,"feedback":"该维度的具体评价"}',
    '  ],',
    '  "comment": "总体评语（100-200字，必须具体指出作文的优点和不足，引用实际内容）",',
    '  "strengths": ["优点1","优点2","优点3"],',
    '  "weaknesses": ["不足1","不足2","不足3"],',
    '  "suggestions": ["改进建议1","改进建议2","改进建议3"]',
    '}',
    '',
    '重要提示：',
    '1. 必须认真阅读作文全文后再评分，不要仅凭字数或关键词给分',
    '2. 评价必须具体，要引用作文中的实际句子或内容来佐证你的评价',
    '3. 如果作文内容质量差（如胡乱凑字、内容空洞、主题不清），必须给低分',
    '4. dimensions数组中4个维度的score之和必须等于totalScore',
    '5. strengths/weaknesses/suggestions各至少2条，最多5条',
    '',
    '作文标题：' + (title || '（无标题）'),
    '',
    '作文正文：',
    content,
  ].join('\n');

  const response = await fetch('https://api.deepseek.com/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.DEEPSEEK_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: env.DEEPSEEK_MODEL || 'deepseek-chat',
      temperature: 0.3,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content: '你是一位严谨的语文教师，只输出符合要求的 JSON 对象。你必须基于作文的实际内容进行评价，绝不敷衍给分。',
        },
        { role: 'user', content: prompt },
      ],
    }),
  });

  const respPayload = (await response.json().catch(() => null)) as {
    choices?: Array<{ message?: { content?: string } }>;
    error?: { message?: string };
  } | null;

  if (!response.ok) {
    throw new Error(`作文批改服务调用失败：${respPayload?.error?.message || response.statusText}`);
  }

  const respContent = respPayload?.choices?.[0]?.message?.content;
  if (!respContent) {
    throw new Error('作文批改服务未返回有效结果。');
  }

  return normalizeEssayResult(parseJsonObject(respContent), content, title);
}

/**
 * 规范化作文批改结果，确保数值合法
 */
function normalizeEssayResult(
  value: Record<string, unknown>,
  content: string,
  title: string,
): {
  totalScore: number;
  grade: string;
  dimensions: Array<{ name: string; max: number; score: number; feedback: string }>;
  comment: string;
  strengths: string[];
  weaknesses: string[];
  suggestions: string[];
} {
  const dimNames = [
    { name: '内容立意', max: 30 },
    { name: '结构布局', max: 20 },
    { name: '语言表达', max: 30 },
    { name: '创新亮点', max: 20 },
  ];

  const rawDims = Array.isArray(value.dimensions) ? value.dimensions : [];
  const dimensions = dimNames.map((dim, i) => {
    const raw = (rawDims[i] || {}) as Record<string, unknown>;
    let score = Math.round(Number(raw.score ?? 0));
    if (isNaN(score) || score < 0) score = 0;
    if (score > dim.max) score = dim.max;
    return {
      name: dim.name,
      max: dim.max,
      score,
      feedback: String(raw.feedback || '').trim() || '该维度暂无具体评价。',
    };
  });

  // 总分 = 四个维度分数之和（确保一致）
  let totalScore = dimensions.reduce((sum, d) => sum + d.score, 0);
  if (totalScore > 100) totalScore = 100;
  if (totalScore < 0) totalScore = 0;

  const grade =
    totalScore >= 90 ? 'A · 优秀' :
    totalScore >= 80 ? 'B · 良好' :
    totalScore >= 70 ? 'C · 中等' :
    totalScore >= 60 ? 'D · 及格' :
    'E · 不及格';

  const comment = String(value.comment || '').trim() ||
    `本文（${title ? '《' + title + '》' : '无标题'}）共${content.length}字，总分${totalScore}分。请参考各维度评价进行改进。`;

  const toStringArray = (arr: unknown, fallback: string[]): string[] => {
    if (!Array.isArray(arr)) return fallback;
    const result = arr
      .map((item) => String(item || '').trim())
      .filter(Boolean)
      .slice(0, 5);
    return result.length >= 2 ? result : fallback;
  };

  return {
    totalScore,
    grade,
    dimensions,
    comment,
    strengths: toStringArray(value.strengths, ['暂无明显优点']),
    weaknesses: toStringArray(value.weaknesses, ['暂无具体不足']),
    suggestions: toStringArray(value.suggestions, ['建议多读多写，持续提升写作水平']),
  };
}

/**
 * 口算批改 OCR：用百度 OCR 识别图片文字，再用 DeepSeek 提取算式和答案。
 */
async function handleMentalMathOcr(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit,
  user: AuthUser,
): Promise<Response> {
  const formData = await request.formData();
  const files: File[] = [];
  for (const entry of formData.getAll('files')) {
    if (isUploadedFile(entry)) files.push(entry);
  }
  if (files.length === 0) {
    throw new HttpError(400, '请先上传口算题图片。');
  }
  if (files.length > 3) {
    throw new HttpError(400, '一次最多上传 3 张口算题图片。');
  }
  const totalSize = files.reduce((s, f) => s + f.size, 0);
  if (totalSize > MAX_TOTAL_FILE_SIZE) {
    throw new HttpError(400, '图片总大小超过 8MB，请压缩后重试。');
  }
  for (const file of files) {
    validateUploadedFile(file);
  }

  assertBaiduConfigured(env);
  assertDeepSeekConfigured(env);

  const allOcrLines: string[] = [];
  for (const file of files) {
    if (!file.type.startsWith('image/')) continue;
    const imageBase64 = await fileToBase64(file);
    const ocrText = await recognizeAccurateBasicWithBaidu(imageBase64, env);
    allOcrLines.push(ocrText);
  }

  const combinedText = allOcrLines.join('\n---\n');
  if (!combinedText.trim()) {
    throw new HttpError(400, 'OCR 未识别到有效文字，请换一张更清晰的图片。');
  }

  const prompt = [
    '你是一位数学教师，以下是 OCR 从口算题图片中识别出的文字（可能有识别错误）：',
    '',
    combinedText,
    '',
    '请从以上文字中提取所有口算算式，每行一条，格式为：算式 = 答案。',
    '例如：3 + 5 = 8',
    '只输出算式，不要输出编号、说明或其他内容。',
    '把 × ÷ 符号保留原样输出。',
    '如果某行明显不是算式，请忽略它。',
  ].join('\n');

  const response = await fetch('https://api.deepseek.com/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.DEEPSEEK_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: env.DEEPSEEK_MODEL || 'deepseek-chat',
      temperature: 0.1,
      messages: [
        { role: 'system', content: '你只输出从 OCR 文字中提取出的数学算式，每行一个，格式如 "1 + 2 = 3"。' },
        { role: 'user', content: prompt },
      ],
    }),
  });

  const payload = (await response.json().catch(() => null)) as {
    choices?: Array<{ message?: { content?: string } }>;
    error?: { message?: string };
  } | null;

  if (!response.ok) {
    throw new Error(`DeepSeek 提取算式失败：${payload?.error?.message || response.statusText}`);
  }

  const content = payload?.choices?.[0]?.message?.content;
  if (!content || !content.trim()) {
    throw new Error('DeepSeek 未返回有效结果。');
  }

  const problems: Array<{ text: string; answer: number }> = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    const match = trimmed.match(/([\d\s+\-×÷\u00d7\u00f7\u2212]+)\s*=\s*(-?\d+\.?\d*)/);
    if (match) {
      const expr = match[1].trim();
      const answer = parseInt(match[2], 10);
      if (!isNaN(answer)) {
        problems.push({ text: expr, answer });
      }
    }
  }

  if (problems.length === 0) {
    throw new HttpError(400, '未能从图片中识别出有效口算题，请确保图片包含数学算式。');
  }

  await logUsage(env, user.id, 'mental_math_ocr', 'baidu-ocr+deepseek', `Extracted ${problems.length} problems`);

  return json({ problems }, 200, corsHeaders);
}

/**
 * 使用 GPT Vision 识别试卷图片，提取题目内容和学生手写答案
 */
async function extractPaperContentWithVision(files: File[], env: Env): Promise<string> {
  const parts: string[] = [];

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    if (!file.type.startsWith('image/')) continue;

    const imageBase64 = await fileToBase64(file);
    const mimeType = file.type || 'image/jpeg';
    const dataUrl = `data:${mimeType};base64,${imageBase64}`;

    const response = await fetch(`${(env.GPT_API_BASE || 'https://geekspace.cloud/v1').replace(/\/+$/, '')}/chat/completions`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.GEEKSPACE_API_KEY || env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: env.OPENAI_MODEL || 'gpt-5.5',
        temperature: 0.1,
        messages: [
          {
            role: 'system',
            content: '你是一个专业的试卷识别助手。你需要仔细识别试卷图片中的所有内容，包括印刷的题目和手写的答案。请严格按照要求输出。',
          },
          {
            role: 'user',
            content: [
              {
                type: 'text',
                text: [
                  '请仔细识别这张试卷图片（第' + (i + 1) + '页）中的所有内容。',
                  '',
                  '识别要求：',
                  '1. 识别每道题的题号、题型、题目内容',
                  '2. 识别学生在每道题上手写的答案（包括手写数字、文字、算式、图形标注等）',
                  '3. 如果是选择题/判断题，识别学生选择的选项（A/B/C/D 或 √/×）',
                  '4. 如果是填空题，识别学生填写的答案',
                  '5. 如果是解答题/计算题，识别学生完整的解答过程',
                  '6. 无论是印刷体还是手写体，都要尽可能准确地识别',
                  '',
                  '输出格式（每道题用如下格式）：',
                  '【题号】第X题',
                  '【题型】选择题/填空题/判断题/解答题/计算题/其他',
                  '【题目】完整的题目内容',
                  '【学生答案】学生写下的答案（如果未作答则写"未作答"）',
                  '---',
                  '',
                  '请逐题输出，不要遗漏任何题目。即使手写字迹不太清晰，也要尽力识别并标注。',
                ].join('\n'),
              },
              { type: 'image_url', image_url: { url: dataUrl } },
            ],
          },
        ],
      }),
    });

    const payload = (await response.json().catch(() => null)) as {
      choices?: Array<{ message?: { content?: string } }>;
      error?: { message?: string };
    } | null;

    if (!response.ok) {
      const errMsg = payload?.error?.message || response.statusText;
      throw new Error(`GPT 试卷识别失败：${errMsg.slice(0, 100)}`);
    }

    const text = payload?.choices?.[0]?.message?.content;
    if (text) {
      parts.push(text.trim());
    }
  }

  const combined = parts.join('\n\n=== 下一页 ===\n\n').trim();
  if (!combined) {
    throw new Error('未能从图片中识别出任何试卷内容，请确保图片清晰且包含试卷内容。');
  }

  return combined.length > MAX_ANALYSIS_TEXT_LENGTH ? combined.slice(0, MAX_ANALYSIS_TEXT_LENGTH) : combined;
}

/**
 * 使用 DeepSeek 逐题批改学生答案
 */
async function gradeWithDeepSeek(recognizedText: string, env: Env): Promise<AnalysisResult> {
  const prompt = [
    '你是一位经验丰富、严谨负责的教师，正在批改学生的试卷。',
    '请根据以下识别到的试卷内容（包含题目和学生答案），逐题进行批改。',
    '',
    '批改要求：',
    '1. 仔细阅读每道题的题目内容',
    '2. 根据题目内容判断正确答案',
    '3. 将学生答案与正确答案进行对比',
    '4. 判断学生答案是否正确：',
    '   - 完全正确：得分率100%',
    '   - 基本正确但有小的计算错误/拼写错误：得分率60-80%',
    '   - 方法正确但结果错误：得分率40-60%',
    '   - 完全错误或未作答：得分率0%',
    '5. 对于解答题/计算题，要考虑解题过程是否完整、方法是否正确',
    '6. 对于选择题/判断题，只有完全选对才给100%，选错给0%',
    '7. 对于填空题，答案完全一致给100%，部分正确给50%',
    '',
    '输出 JSON 对象，包含以下字段：',
    '- summary: 批改总结',
    '- subject: 学科',
    '- grade: 年级',
    '- questionCount: 题目总数',
    '- knowledgeCoverage: 知识点覆盖（数组，每项含name和count）',
    '- difficultyDistribution: 难度分布（easy/medium/hard）',
    '- questionTypes: 题型分布（数组，每项含type和count）',
    '- weakPoints: 薄弱知识点列表',
    '- lectureSuggestions: 讲评建议',
    '- questions: 题目数组，每项必须包含：',
    '  - type: 题型',
    '  - knowledgePoints: 知识点数组',
    '  - difficulty: 简单/中等/困难',
    '  - score: 满分',
    '  - scoreRate: 得分率（0-100的整数，基于答案正确性给出）',
    '  - question: 题目内容',
    '  - answer: 正确答案',
    '  - studentAnswer: 学生写的答案',
    '  - isCorrect: true/false（是否完全正确）',
    '  - feedback: 批改评语（说明扣分原因）',
    '',
    '不要输出 Markdown，直接输出 JSON 对象。',
    '',
    '识别到的试卷内容：',
    recognizedText.slice(0, MAX_ANALYSIS_TEXT_LENGTH),
  ].join('\n');

  const response = await fetch('https://api.deepseek.com/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.DEEPSEEK_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: env.DEEPSEEK_MODEL || 'deepseek-chat',
      temperature: 0.2,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content: '你只输出符合要求的 JSON 对象。批改要严格、客观、准确，基于学生实际作答内容评分。',
        },
        { role: 'user', content: prompt },
      ],
    }),
  });

  const payload = (await response.json().catch(() => null)) as {
    choices?: Array<{ message?: { content?: string } }>;
    error?: { message?: string };
  } | null;

  if (!response.ok) {
    throw new Error(`DeepSeek 批改失败：${payload?.error?.message || response.statusText}`);
  }

  const content = payload?.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error('DeepSeek 未返回有效批改结果。');
  }

  return normalizeAnalysis(parseJsonObject(content));
}

/**
 * 更新数据库中题目的得分率
 */
async function updateQuestionScores(env: Env, user: AuthUser, questions: Required<Question>[]): Promise<void> {
  // 批改结果直接更新最近一次分析的题目得分率
  const recentQuestions = await env.DB.prepare(
    'SELECT id FROM questions WHERE user_id = ? ORDER BY created_at DESC LIMIT ?',
  )
    .bind(user.id, questions.length)
    .all<{ id: string }>();

  const existingIds = (recentQuestions.results || []).map((r) => r.id);
  const now = new Date().toISOString();

  for (let i = 0; i < questions.length && i < existingIds.length; i++) {
    const q = questions[i];
    const questionId = existingIds[i];
    await env.DB.prepare(
      'UPDATE questions SET score_rate = ?, answer = ? WHERE id = ? AND user_id = ?',
    )
      .bind(
        Math.round(Number(q.scoreRate) || 0),
        String(q.answer || q.studentAnswer || q.analysis || '').slice(0, 2000),
        questionId,
        user.id,
      )
      .run();
  }
}

async function buildDefaultAnalysisText(files: File[], textParts: string[], env: Env): Promise<string> {
  const parts = [...textParts];

  for (const file of files) {
    if (file.type.startsWith('image/')) {
      const imageBase64 = await fileToBase64(file);
      parts.push(await recognizeWithBaidu(imageBase64, env));
    }
  }

  const combined = parts.join('\n\n---\n\n').trim();
  if (!combined) {
    throw new HttpError(400, '默认方式需要图片 OCR 内容或可提取文字的 PDF。扫描版 PDF 请先转成图片上传。');
  }

  if (combined.length > MAX_ANALYSIS_TEXT_LENGTH) {
    return combined.slice(0, MAX_ANALYSIS_TEXT_LENGTH);
  }

  return combined;
}

async function extractTextWithGPTVision(files: File[], textParts: string[], env: Env): Promise<string> {
  const parts = [...textParts];

  for (const file of files) {
    if (!file.type.startsWith('image/')) continue;

    const imageBase64 = await fileToBase64(file);
    const mimeType = file.type || 'image/jpeg';
    const dataUrl = `data:${mimeType};base64,${imageBase64}`;

    const response = await fetch(`${(env.GPT_API_BASE || 'https://geekspace.cloud/v1').replace(/\/+$/, '')}/chat/completions`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.GEEKSPACE_API_KEY || env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: env.OPENAI_MODEL || 'gpt-5.5',
        temperature: 0.1,
        messages: [
          {
            role: 'system',
            content: '你只输出识别出的文字内容，不要进行任何分析、评价或补充。',
          },
          {
            role: 'user',
            content: [
              { type: 'text', text: '请识别并提取这张试卷图片中的所有文字内容，保持原有的格式和排版结构，包括题目、选项、分值、公式等。直接输出文字，不要加任何说明。' },
              { type: 'image_url', image_url: { url: dataUrl } },
            ],
          },
        ],
      }),
    });

    const payload = (await response.json().catch(() => null)) as {
      choices?: Array<{ message?: { content?: string } }>;
      error?: { message?: string };
    } | null;

    if (!response.ok) {
      const errMsg = payload?.error?.message || response.statusText;
      throw new Error(`GPT 图片识别失败：${errMsg.slice(0, 100)}`);
    }

    const text = payload?.choices?.[0]?.message?.content;
    if (text) {
      parts.push(text.trim());
    }
  }

  const combined = parts.join('\n\n---\n\n').trim();
  if (!combined) {
    throw new Error('多模态方式需要上传试卷图片或可提取文字的 PDF。');
  }

  return combined.length > MAX_ANALYSIS_TEXT_LENGTH ? combined.slice(0, MAX_ANALYSIS_TEXT_LENGTH) : combined;
}

async function handleListQuestions(env: Env, corsHeaders: HeadersInit, user: AuthUser): Promise<Response> {
  const rows = await env.DB.prepare(
    [
      'SELECT questions.id, questions.type, questions.knowledge_points, questions.difficulty,',
      'questions.score, questions.score_rate, questions.question, questions.answer,',
      'papers.title AS paper_title, papers.created_at AS paper_created_at',
      'FROM questions',
      'LEFT JOIN papers ON papers.id = questions.paper_id',
      'WHERE questions.user_id = ?',
      'ORDER BY questions.created_at DESC',
      'LIMIT 1000',
    ].join(' '),
  )
    .bind(user.id)
    .all<{
      id: string;
      type: string;
      knowledge_points: string;
      difficulty: string;
      score: number;
      score_rate: number;
      question: string;
      answer: string | null;
      paper_title: string | null;
      paper_created_at: string | null;
    }>();

  const questions = (rows.results || []).map((row) => ({
    id: row.id,
    type: row.type,
    knowledgePoints: safeJsonArray(row.knowledge_points),
    difficulty: row.difficulty,
    score: row.score,
    scoreRate: row.score_rate,
    question: row.question,
    answer: row.answer || '',
    paperTitle: row.paper_title || '',
    paperCreatedAt: row.paper_created_at || '',
  }));

  return json({ questions }, 200, corsHeaders);
}

async function handleClearQuestions(env: Env, corsHeaders: HeadersInit, user: AuthUser): Promise<Response> {
  await env.DB.prepare('DELETE FROM paper_files WHERE paper_id IN (SELECT id FROM papers WHERE user_id = ?)').bind(user.id).run();
  await env.DB.prepare('DELETE FROM questions WHERE user_id = ?').bind(user.id).run();
  await env.DB.prepare('DELETE FROM papers WHERE user_id = ?').bind(user.id).run();
  await logUsage(env, user.id, 'clear_questions', null, 'user cleared question database');
  return json({ ok: true }, 200, corsHeaders);
}

async function handleListStudents(env: Env, corsHeaders: HeadersInit, user: AuthUser): Promise<Response> {
  const rows = await env.DB.prepare(
    [
      'SELECT id, student_no, name, class_name, avg_rate, total_questions, kp_data, created_at, updated_at',
      'FROM students',
      'WHERE user_id = ?',
      'ORDER BY updated_at DESC, created_at DESC',
      'LIMIT 1000',
    ].join(' '),
  )
    .bind(user.id)
    .all<{
      id: string;
      student_no: string;
      name: string;
      class_name: string;
      avg_rate: number;
      total_questions: number;
      kp_data: string;
      created_at: string;
      updated_at: string;
    }>();

  const students = (rows.results || []).map((row) => ({
    dbId: row.id,
    id: row.student_no,
    name: row.name,
    class: row.class_name,
    avgRate: row.avg_rate,
    totalQuestions: row.total_questions,
    kpData: safeJsonObject(row.kp_data),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));

  return json({ students }, 200, corsHeaders);
}

async function handleCreateStudent(
  request: Request,
  env: Env,
  corsHeaders: HeadersInit,
  user: AuthUser,
): Promise<Response> {
  const payload = (await request.json().catch(() => null)) as StudentPayload | null;
  const studentNo = normalizeStudentText(payload?.id, 32);
  const name = normalizeStudentText(payload?.name, 40);
  const className = normalizeStudentText(payload?.class, 60);
  const avgRate = clamp(numberOrDefault(payload?.avgRate, 60), 0, 100);
  const totalQuestions = Math.max(0, Math.round(numberOrDefault(payload?.totalQuestions, 0)));
  const kpData = normalizeKpData(payload?.kpData, avgRate);

  if (!name) throw new HttpError(400, '请输入学生姓名。');
  if (!studentNo) throw new HttpError(400, '请输入学号。');
  if (!className) throw new HttpError(400, '请选择或输入班级。');

  const existing = await env.DB.prepare('SELECT id FROM students WHERE user_id = ? AND student_no = ?')
    .bind(user.id, studentNo)
    .first<{ id: string }>();
  if (existing) {
    throw new HttpError(409, `学号 ${studentNo} 已存在。`);
  }

  const now = new Date().toISOString();
  const dbId = crypto.randomUUID();
  await env.DB.prepare(
    [
      'INSERT INTO students',
      '(id, user_id, student_no, name, class_name, avg_rate, total_questions, kp_data, created_at, updated_at)',
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ].join(' '),
  )
    .bind(dbId, user.id, studentNo, name, className, avgRate, totalQuestions, JSON.stringify(kpData), now, now)
    .run();

  await logUsage(env, user.id, 'create_student', null, JSON.stringify({ studentNo, className }));

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
        updatedAt: now,
      },
    },
    200,
    corsHeaders,
  );
}

async function savePaperResult(
  env: Env,
  user: AuthUser,
  input: {
    title: string;
    mode: string;
    provider: string;
    files: File[];
    textParts: string[];
    result: AnalysisResult;
  },
): Promise<StoredPaper> {
  const now = new Date().toISOString();
  const paperId = crypto.randomUUID();
  const questions = normalizeQuestions(input.result.questions || []);

  await env.DB.prepare(
    [
      'INSERT INTO papers',
      '(id, user_id, title, mode, source_text_preview, summary, subject, grade, question_count, created_at, updated_at)',
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ].join(' '),
  )
    .bind(
      paperId,
      user.id,
      input.title,
      input.mode,
      input.result.originalTextPreview || input.textParts.join('\n\n').slice(0, 1200),
      input.result.summary,
      input.result.subject || '',
      input.result.grade || '',
      questions.length,
      now,
      now,
    )
    .run();

  for (const file of input.files) {
    await env.DB.prepare(
      'INSERT INTO paper_files (id, paper_id, file_name, mime_type, file_size, extracted_text_preview, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
    )
      .bind(crypto.randomUUID(), paperId, file.name || 'upload', file.type || 'application/octet-stream', file.size, '', now)
      .run();
  }

  for (const question of questions) {
    await env.DB.prepare(
      [
        'INSERT INTO questions',
        '(id, paper_id, user_id, type, knowledge_points, difficulty, score, score_rate, question, answer, created_at)',
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      ].join(' '),
    )
      .bind(
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
        now,
      )
      .run();
  }

  await logUsage(env, user.id, 'analyze_paper', input.provider, JSON.stringify({ mode: input.mode, files: input.files.length }));

  return {
    id: paperId,
    title: input.title,
    mode: input.mode,
    createdAt: now,
    questionCount: questions.length,
  };
}

async function recognizeWithBaidu(imageBase64: string, env: Env): Promise<string> {
  const mode = env.BAIDU_OCR_MODE || 'auto';
  if (mode === 'formula') {
    return recognizeFormulaWithBaidu(imageBase64, env);
  }

  if (mode === 'auto') {
    try {
      const formulaText = await recognizeFormulaWithBaidu(imageBase64, env);
      if (looksLikeUsefulMathText(formulaText)) return formulaText;
    } catch {
      // Formula OCR is best-effort; fall back to accurate text OCR.
    }
  }

  return recognizeAccurateBasicWithBaidu(imageBase64, env);
}

async function recognizeAccurateBasicWithBaidu(imageBase64: string, env: Env): Promise<string> {
  const accessToken = await getBaiduAccessToken(env);
  const body = new URLSearchParams({
    image: imageBase64,
    language_type: 'CHN_ENG',
    detect_direction: 'true',
    paragraph: 'true',
  });

  const response = await fetch(`https://aip.baidubce.com/rest/2.0/ocr/v1/accurate_basic?access_token=${accessToken}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });

  const payload = (await response.json()) as {
    words_result?: Array<{ words: string }>;
    error_msg?: string;
  };

  if (!response.ok || payload.error_msg) {
    throw new Error(`百度 OCR 识别失败：${payload.error_msg || response.statusText}`);
  }

  const text = payload.words_result?.map((item) => item.words).join('\n').trim() ?? '';
  if (!text) {
    throw new Error('OCR 未识别到有效文字，请换一张更清晰的试卷图片。');
  }

  return text;
}

async function recognizeFormulaWithBaidu(imageBase64: string, env: Env): Promise<string> {
  const accessToken = await getBaiduAccessToken(env);
  const response = await fetch(`https://aip.baidubce.com/rest/2.0/ocr/v1/formula?access_token=${accessToken}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ image: imageBase64 }),
  });

  const payload = (await response.json()) as {
    words_result?: Array<{ words?: string; formula?: string }>;
    formula_result?: Array<{ words?: string; formula?: string }>;
    error_msg?: string;
  };

  if (!response.ok || payload.error_msg) {
    throw new Error(`百度公式 OCR 识别失败：${payload.error_msg || response.statusText}`);
  }

  const items = payload.formula_result ?? payload.words_result ?? [];
  const text = items
    .map((item) => item.formula || item.words || '')
    .filter(Boolean)
    .join('\n')
    .trim();

  if (!text) {
    throw new Error('公式 OCR 未识别到有效文字。');
  }

  return text;
}

async function getBaiduAccessToken(env: Env): Promise<string> {
  const response = await fetch('https://aip.baidubce.com/oauth/2.0/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: env.BAIDU_OCR_API_KEY || '',
      client_secret: env.BAIDU_OCR_SECRET_KEY || '',
    }),
  });

  const payload = (await response.json()) as {
    access_token?: string;
    error_description?: string;
  };

  if (!response.ok || !payload.access_token) {
    throw new Error(`百度 access_token 获取失败：${payload.error_description || response.statusText}`);
  }

  return payload.access_token;
}

async function analyzeWithDeepSeek(ocrText: string, env: Env): Promise<AnalysisResult> {
  const prompt = [
    '你是面向中小学教师的试卷分析助手。',
    '请根据试卷文本识别题目并分析试卷，严格输出 JSON 对象，不要输出 Markdown。',
    'JSON 字段必须包含 summary, subject, grade, questionCount, knowledgeCoverage, difficultyDistribution, questionTypes, weakPoints, lectureSuggestions, questions。',
    'questions 是题目数组，每项包含 type, knowledgePoints, difficulty, score, question, answer。',
    'difficulty 只能使用 简单、中等、困难；type 优先使用 选择题、填空题、解答题、判断题、其他。',
    '不要输出或估计得分率，得分率只属于阅卷结果，不属于试卷结构分析。',
    '如果题目信息不完整，请基于可见内容做概括性分析；不要评价 OCR 质量或识别过程。',
    '',
    '试卷文本：',
    ocrText.slice(0, MAX_ANALYSIS_TEXT_LENGTH),
  ].join('\n');

  const response = await fetch('https://api.deepseek.com/chat/completions', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.DEEPSEEK_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: env.DEEPSEEK_MODEL || 'deepseek-chat',
      temperature: 0.2,
      response_format: { type: 'json_object' },
      messages: [
        {
          role: 'system',
          content: '你只输出符合要求的 JSON 对象，字段缺失时使用合理默认值。',
        },
        { role: 'user', content: prompt },
      ],
    }),
  });

  const payload = (await response.json().catch(() => null)) as {
    choices?: Array<{ message?: { content?: string } }>;
    error?: { message?: string };
  } | null;

  if (!response.ok) {
    throw new Error(`DeepSeek 分析失败：${payload?.error?.message || response.statusText}`);
  }

  const content = payload?.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error('DeepSeek 未返回有效分析结果。');
  }

  return normalizeAnalysis(parseJsonObject(content));
}

function parseJsonObject<T = Record<string, unknown>>(content: string): T {
  try {
    return JSON.parse(content) as T;
  } catch {
    const match = content.match(/\{[\s\S]*\}/);
    if (!match) throw new Error('模型返回内容不是有效 JSON。');
    return JSON.parse(match[0]) as T;
  }
}

function normalizeAnalysis(value: Partial<AnalysisResult>): AnalysisResult {
  const questions = normalizeQuestions(Array.isArray(value.questions) ? value.questions : []);

  return {
    summary: value.summary || '已完成试卷结构与讲评重点分析。',
    subject: value.subject || '',
    grade: value.grade || '',
    questionCount: numberOrUndefined(value.questionCount) || questions.length,
    knowledgeCoverage: Array.isArray(value.knowledgeCoverage) ? value.knowledgeCoverage.slice(0, 12) : [],
    difficultyDistribution: {
      easy: Number(value.difficultyDistribution?.easy ?? 0),
      medium: Number(value.difficultyDistribution?.medium ?? 0),
      hard: Number(value.difficultyDistribution?.hard ?? 0),
    },
    questionTypes: Array.isArray(value.questionTypes) ? value.questionTypes.slice(0, 12) : [],
    weakPoints: Array.isArray(value.weakPoints) ? value.weakPoints.slice(0, 8) : [],
    lectureSuggestions: Array.isArray(value.lectureSuggestions) ? value.lectureSuggestions.slice(0, 8) : [],
    questions,
    originalTextPreview: '',
  };
}

function normalizeQuestions(questions: Question[]): Required<Question>[] {
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
      question: String(question.question || question.content || question.text || '未识别题目').trim(),
      content: String(question.content || question.question || question.text || '').trim(),
      text: String(question.text || question.question || question.content || '').trim(),
      answer: String(question.answer || question.analysis || '').trim(),
      analysis: String(question.analysis || question.answer || '').trim(),
      studentAnswer: String(question.studentAnswer || '').trim(),
      isCorrect: question.isCorrect === true,
      feedback: String(question.feedback || '').trim(),
    };
  });
}

async function withSessionCookie(request: Request, env: Env, corsHeaders: HeadersInit, user: AuthUser): Promise<Response> {
  const token = randomToken();
  const tokenHash = await sha256Hex(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_SECONDS * 1000).toISOString();

  await env.DB.prepare('DELETE FROM sessions WHERE user_id = ? OR expires_at <= ?').bind(user.id, now.toISOString()).run();
  await env.DB.prepare('INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
    .bind(crypto.randomUUID(), user.id, tokenHash, now.toISOString(), expiresAt)
    .run();

  return json(
    { user },
    200,
    {
      ...corsHeaders,
      'Set-Cookie': makeSessionCookie(request, token),
    },
  );
}

async function getCurrentUser(request: Request, env: Env): Promise<AuthUser | null> {
  assertDatabaseConfigured(env);
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return null;

  const tokenHash = await sha256Hex(token);
  const row = await env.DB.prepare(
    [
      'SELECT users.id, users.email, users.name, users.created_at',
      'FROM sessions',
      'JOIN users ON users.id = sessions.user_id',
      'WHERE sessions.token_hash = ? AND sessions.expires_at > ?',
      'LIMIT 1',
    ].join(' '),
  )
    .bind(tokenHash, new Date().toISOString())
    .first<{ id: string; email: string; name: string; created_at: string }>();

  if (!row) return null;
  return { id: row.id, email: row.email, name: row.name, createdAt: row.created_at };
}

async function requireUser(request: Request, env: Env): Promise<AuthUser> {
  const user = await getCurrentUser(request, env);
  if (!user) throw new AuthError('请先登录后再使用该功能。');
  return user;
}

async function getUserById(env: Env, userId: string): Promise<AuthUser | null> {
  const row = await env.DB.prepare('SELECT id, email, name, created_at FROM users WHERE id = ?')
    .bind(userId)
    .first<{ id: string; email: string; name: string; created_at: string }>();

  if (!row) return null;
  return { id: row.id, email: row.email, name: row.name, createdAt: row.created_at };
}

async function logUsage(
  env: Env,
  userId: string,
  eventType: string,
  provider: string | null,
  detail: string,
): Promise<void> {
  await env.DB.prepare(
    'INSERT INTO usage_events (id, user_id, event_type, provider, detail, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  )
    .bind(crypto.randomUUID(), userId, eventType, provider, detail, new Date().toISOString())
    .run();
}

function validateUploadedFile(file: File): void {
  if (file.size > MAX_FILE_SIZE) {
    throw new HttpError(400, `文件 ${file.name || ''} 超过 4MB，请压缩后重试。`);
  }

  const supported = file.type.startsWith('image/') || file.type === 'application/pdf';
  if (!supported) {
    throw new HttpError(400, '仅支持 JPG、PNG、WEBP 图片或可提取文字的 PDF。');
  }
}

function isUploadedFile(value: unknown): value is File {
  return typeof value === 'object' && value !== null && 'arrayBuffer' in value && 'size' in value && 'type' in value;
}

function inferPaperTitle(files: File[]): string {
  if (files.length === 0) return `试卷分析 ${new Date().toLocaleDateString('zh-CN')}`;
  if (files.length === 1) return files[0].name || '试卷分析';
  return `${files[0].name || '试卷'} 等 ${files.length} 个文件`;
}

function safeJsonArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed.map(String);
  } catch {
    // Fall through.
  }
  return value ? [value] : ['未分类'];
}

function safeJsonObject(value: string): Record<string, number> {
  try {
    const parsed = JSON.parse(value);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const result: Record<string, number> = {};
      for (const [key, rawValue] of Object.entries(parsed)) {
        const normalizedKey = String(key).trim();
        if (!normalizedKey) continue;
        result[normalizedKey] = clamp(numberOrDefault(rawValue, 0), 0, 100);
      }
      return result;
    }
  } catch {
    // Fall through.
  }
  return {};
}

function normalizeStudentText(value: unknown, maxLength: number): string {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

function normalizeKpData(value: unknown, avgRate: number): Record<string, number> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};

  const result: Record<string, number> = {};
  for (const [key, rawValue] of Object.entries(value)) {
    const normalizedKey = key.trim().slice(0, 60);
    if (!normalizedKey) continue;
    result[normalizedKey] = clamp(numberOrDefault(rawValue, avgRate), 0, 100);
  }

  return result;
}

function normalizeQuestionType(type: unknown): string {
  const text = String(type || '').trim();
  if (['选择题', '填空题', '解答题', '判断题', '其他'].includes(text)) return text;
  return '其他';
}

function normalizeDifficulty(difficulty: unknown): string {
  const text = String(difficulty || '').trim();
  if (['简单', '中等', '困难'].includes(text)) return text;
  if (['easy', 'low'].includes(text.toLowerCase())) return '简单';
  if (['hard', 'high'].includes(text.toLowerCase())) return '困难';
  return '中等';
}

function normalizeKnowledgePoints(value: unknown): string[] {
  const list = Array.isArray(value) ? value : value ? [value] : ['未分类'];
  const normalized = list.map((item) => String(item).trim()).filter(Boolean);
  return normalized.length > 0 ? normalized.slice(0, 8) : ['未分类'];
}

function numberOrUndefined(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : undefined;
  }
  return undefined;
}

function numberOrDefault(value: unknown, fallback: number): number {
  return numberOrUndefined(value) ?? fallback;
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

function looksLikeUsefulMathText(text: string): boolean {
  const compact = text.replace(/\s/g, '');
  if (compact.length < 80) return false;
  return ['\\frac', '\\sqrt', '\\sin', '\\cos', '\\tan', '^', '_', '{', '}'].some((signal) => compact.includes(signal));
}

async function fileToBase64(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;

  for (let index = 0; index < bytes.length; index += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunkSize));
  }

  return btoa(binary);
}

function assertDatabaseConfigured(env: Env): void {
  if (!env.DB) throw new Error('后端缺少 D1 数据库绑定：DB');
}

function assertBaiduConfigured(env: Env): void {
  assertKeys([
    ['BAIDU_OCR_API_KEY', env.BAIDU_OCR_API_KEY],
    ['BAIDU_OCR_SECRET_KEY', env.BAIDU_OCR_SECRET_KEY],
  ]);
}

function assertDeepSeekConfigured(env: Env): void {
  assertKeys([['DEEPSEEK_API_KEY', env.DEEPSEEK_API_KEY]]);
}

function assertOpenAiConfigured(env: Env): void {
  assertKeys([['GEEKSPACE_API_KEY 或 OPENAI_API_KEY', env.GEEKSPACE_API_KEY || env.OPENAI_API_KEY]]);
}

function assertKeys(entries: Array<[string, string | undefined]>): void {
  const missing = entries.filter(([, value]) => !value).map(([key]) => key);
  if (missing.length > 0) {
    throw new Error(`后端缺少环境变量：${missing.join(', ')}`);
  }
}

function getCorsHeaders(env: Env, request: Request): HeadersInit {
  const origin = request.headers.get('Origin');
  const configuredOrigins = (env.ALLOWED_ORIGINS || env.ALLOWED_ORIGIN || '*')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  const allowAny = configuredOrigins.includes('*');
  const allowOrigin =
    allowAny && origin
      ? origin
      : origin && configuredOrigins.includes(origin)
        ? origin
        : configuredOrigins[0] || '*';

  return {
    'Access-Control-Allow-Origin': allowOrigin,
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  };
}

function json(data: unknown, status: number, headers: HeadersInit): Response {
  return Response.json(data, {
    status,
    headers: {
      ...headers,
      'Content-Type': 'application/json; charset=utf-8',
    },
  });
}

function getErrorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

class AuthError extends Error {}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function normalizeEmail(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function normalizeName(value: unknown, email: string): string {
  const name = typeof value === 'string' ? value.trim() : '';
  return name || email.split('@')[0] || '老师';
}

function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function hashPassword(password: string): Promise<{ hash: string; salt: string }> {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derivePasswordHash(password, saltBytes, PASSWORD_ITERATIONS);
  return {
    hash: bytesToBase64(hash),
    salt: bytesToBase64(saltBytes),
  };
}

async function verifyPassword(password: string, salt: string, expectedHash: string, iterations: number): Promise<boolean> {
  const saltBytes = base64ToBytes(salt);
  const hash = await derivePasswordHash(password, saltBytes, iterations || PASSWORD_ITERATIONS);
  return timingSafeEqual(bytesToBase64(hash), expectedHash);
}

async function derivePasswordHash(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return new Uint8Array(bits);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= a.charCodeAt(index) ^ b.charCodeAt(index);
  return diff === 0;
}

function randomToken(): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function makeSessionCookie(request: Request, token: string): string {
  const isHttps = new URL(request.url).protocol === 'https:';
  const sameSite = isHttps ? 'None' : 'Lax';
  const secure = isHttps ? '; Secure' : '';
  return `${SESSION_COOKIE}=${token}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_SECONDS}; SameSite=${sameSite}${secure}`;
}

function clearSessionCookie(request: Request): string {
  const isHttps = new URL(request.url).protocol === 'https:';
  const sameSite = isHttps ? 'None' : 'Lax';
  const secure = isHttps ? '; Secure' : '';
  return `${SESSION_COOKIE}=; HttpOnly; Path=/; Max-Age=0; SameSite=${sameSite}${secure}`;
}

function getCookie(request: Request, name: string): string {
  const cookie = request.headers.get('Cookie') || '';
  return (
    cookie
      .split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith(`${name}=`))
      ?.slice(name.length + 1) || ''
  );
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
