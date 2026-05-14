export type RuleType = "patterns" | "deps" | "both";

export interface DetectResult {
  stacks: string[];
  ruleType: RuleType;
}

// Intent-keyword signals — matched against lowercased intent text
const STACK_SIGNALS: Record<string, string[]> = {
  nextjs:      ["next.js", "nextjs", "next/", "app router", "server action", "server component", "pages/api", "use client", "use server"],
  express:     ["express", "req, res", "app.get(", "app.post(", "router.", "express()"],
  fastapi:     ["fastapi", "uvicorn", "@app.get", "@app.post", "@router", "pydantic"],
  nestjs:      ["nestjs", "nest.js", "@controller", "@injectable", "@module", "@get(", "@post("],
  nuxt:        ["nuxt", "defineeventhandler", "usefetch", "useasyncdata", "nuxt.config"],
  "react-spa": ["react", "vite", "create-react-app", "usestate(", "useeffect(", "jsx", "tsx"],
  django:      ["django", "views.py", "urls.py", "models.py", "settings.py", "manage.py"],
  rails:       ["rails", "activerecord", "actioncontroller", "gemfile", "ruby on rails"],
  go:          ["golang", "gin", "echo", "fiber", "net/http", "func main()"],
};

// File-path signals — matched against the lowercased file path only.
// These fire when the developer's open file implies the stack without
// "nextjs" or "fastapi" appearing in the intent text.
const FILE_PATH_SIGNALS: Record<string, string[]> = {
  nextjs:      ["next.config", "app/api/", "app/page.", "pages/api/", "app/(", "/app/layout.", "next-env.d.ts"],
  express:     ["app.js", "server.js", "routes/", "/middleware/", "bin/www"],
  fastapi:     ["requirements.txt", "pyproject.toml", "/routers/", "main.py", "alembic.ini"],
  nestjs:      ["nest-cli.json", ".controller.ts", ".service.ts", ".module.ts", ".guard.ts"],
  nuxt:        ["nuxt.config", "/composables/", "/server/api/", ".vue", "/plugins/"],
  "react-spa": ["vite.config", "src/app.tsx", "src/app.jsx", "src/components/", "craco.config"],
  django:      ["settings.py", "views.py", "models.py", "urls.py", "manage.py", "wsgi.py", "asgi.py"],
  rails:       ["gemfile", "app/controllers/", "app/models/", "config/routes.rb", "db/schema.rb"],
  go:          ["go.mod", "go.sum", "/cmd/", "/internal/", "/pkg/", ".go"],
};

const PATTERNS_SIGNALS = [
  "implement", "build", "add", "create", "write", "auth", "upload",
  "fetch", "route", "api", "middleware", "form", "validate", "sanitize",
  "secure", "security", "login", "token", "session", "cookie", "header",
  "redirect", "cors", "csrf", "xss", "injection", "permission", "access",
];

const DEPS_SIGNALS = [
  "install", "npm install", "package", "dependency", "upgrade",
  "library", "import", "use library", "yarn add", "pnpm add",
  "update", "version", "module",
];

export function detectContext(
  intent: string,
  filePath?: string,
  explicitStacks?: string[]
): DetectResult {
  const intentLower  = intent.toLowerCase();
  const filePathLower = (filePath ?? "").toLowerCase();
  const combined     = `${intentLower} ${filePathLower}`;

  // Stack detection — merge intent signals + file-path signals
  const detectedStacks: string[] = explicitStacks?.length
    ? explicitStacks
    : Object.keys(STACK_SIGNALS).filter(slug => {
        const intentHit  = STACK_SIGNALS[slug].some(s => intentLower.includes(s));
        const fileHit    = filePathLower && FILE_PATH_SIGNALS[slug]?.some(s => filePathLower.includes(s));
        return intentHit || fileHit;
      });

  // Rule type detection — uses combined haystack
  const hasPatterns = PATTERNS_SIGNALS.some(s => combined.includes(s));
  const hasDeps     = DEPS_SIGNALS.some(s => combined.includes(s));

  let ruleType: RuleType;
  if (hasPatterns && hasDeps) ruleType = "both";
  else if (hasDeps)           ruleType = "deps";
  else                        ruleType = "patterns"; // default: coding context

  return { stacks: detectedStacks, ruleType };
}
