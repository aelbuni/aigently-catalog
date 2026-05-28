export type CatalogStatus = "launch" | "coming_soon";

export interface StackConfig {
  // ── DB identity (seed.ts writes these to `stack` table) ──────────────
  slug: string;
  name: string;
  catalogStatus: CatalogStatus;
  sortOrder: number;
  ecosystem: string; // "npm" | "pypi" | "rubygems" | "go" | "swift" | "maven"

  // ── OSV.dev Phase 2 ──────────────────────────────────────────────────
  osvEcosystem: string; // sent to OSV API: "npm" | "PyPI" | "Go" | "RubyGems" | "Maven" | "SwiftURL"
  osvPackages: string[];

  // ── NVD Phase 4 ──────────────────────────────────────────────────────
  nvdKeywords: string[]; // stored in stack.nvd_keywords

  // ── GitHub Advisory Phase 3 ──────────────────────────────────────────
  ghsaEcosystem: string; // "NPM" | "PIP" | "RUBYGEMS" | "GO" | "MAVEN" | "SWIFT"

  // ── npm Audit Phase 1 (npm stacks only) ──────────────────────────────
  npmPackages?: Record<string, string>;

  // ── Ingestion filters ────────────────────────────────────────────────
  cwePriority: string[];
  minCvss: number;
}

export const STACK_REGISTRY: StackConfig[] = [
  // ── LAUNCH ─────────────────────────────────────────────────────────────
  {
    slug: "nextjs",
    name: "Next.js",
    catalogStatus: "launch",
    sortOrder: 1,
    ecosystem: "npm",
    osvEcosystem: "npm",
    osvPackages: [
      "next",
      "react",
      "react-dom",
      "react-server-dom-webpack",
      "react-server-dom-turbopack",
    ],
    nvdKeywords: ["next.js", "nextjs", "vercel next"],
    ghsaEcosystem: "NPM",
    npmPackages: {
      next: "14.0.0",
      react: "18.0.0",
      "react-dom": "18.0.0",
      jsonwebtoken: "8.5.1",
      axios: "0.21.1",
      lodash: "4.17.20",
      "node-fetch": "2.6.1",
    },
    cwePriority: [
      "CWE-798", "CWE-502", "CWE-79", "CWE-352", "CWE-1321",
      "CWE-22",  "CWE-918", "CWE-285", "CWE-863", "CWE-400",
    ],
    minCvss: 7.0,
  },
  {
    slug: "express",
    name: "Express / Node.js",
    catalogStatus: "launch",
    sortOrder: 2,
    ecosystem: "npm",
    osvEcosystem: "npm",
    osvPackages: [
      "express", "body-parser", "multer", "cors",
      "jsonwebtoken", "mongoose", "sequelize", "helmet",
    ],
    nvdKeywords: ["express.js", "expressjs", "node express"],
    ghsaEcosystem: "NPM",
    npmPackages: {
      express: "4.17.1",
      jsonwebtoken: "8.5.1",
      cors: "2.8.5",
      multer: "1.4.4",
      lodash: "4.17.20",
      mongoose: "5.13.14",
      sequelize: "6.6.5",
    },
    cwePriority: [
      "CWE-22", "CWE-89", "CWE-1321", "CWE-116", "CWE-352",
      "CWE-798", "CWE-400", "CWE-78", "CWE-502",
    ],
    minCvss: 7.0,
  },
  {
    slug: "fastapi",
    name: "FastAPI / Python",
    catalogStatus: "launch",
    sortOrder: 3,
    ecosystem: "pypi",
    osvEcosystem: "PyPI",
    osvPackages: [
      "fastapi", "starlette", "uvicorn", "pydantic",
      "python-jose", "passlib", "fastapi-guard",
    ],
    nvdKeywords: ["fastapi", "starlette", "pydantic"],
    ghsaEcosystem: "PIP",
    cwePriority: [
      "CWE-284", "CWE-89", "CWE-346", "CWE-942", "CWE-400",
      "CWE-20",  "CWE-352", "CWE-94", "CWE-798",
    ],
    minCvss: 7.0,
  },
  {
    slug: "nestjs",
    name: "NestJS",
    catalogStatus: "launch",
    sortOrder: 4,
    ecosystem: "npm",
    osvEcosystem: "npm",
    osvPackages: [
      "@nestjs/core", "@nestjs/common", "@nestjs/platform-express",
      "@nestjs/jwt", "@nestjs/passport",
    ],
    nvdKeywords: ["nestjs", "nest.js"],
    ghsaEcosystem: "NPM",
    npmPackages: {
      "@nestjs/core": "9.0.0",
      "@nestjs/common": "9.0.0",
      jsonwebtoken: "8.5.1",
      axios: "0.21.1",
      lodash: "4.17.20",
    },
    cwePriority: [
      "CWE-89", "CWE-79", "CWE-352", "CWE-798",
      "CWE-400", "CWE-285", "CWE-1321",
    ],
    minCvss: 7.0,
  },
  {
    slug: "nuxt",
    name: "Nuxt",
    catalogStatus: "launch",
    sortOrder: 5,
    ecosystem: "npm",
    osvEcosystem: "npm",
    osvPackages: ["nuxt", "@nuxt/kit", "@nuxt/schema", "h3", "nitro"],
    nvdKeywords: ["nuxt.js", "nuxtjs", "nuxt framework"],
    ghsaEcosystem: "NPM",
    npmPackages: {
      nuxt: "3.0.0",
      axios: "0.21.1",
      lodash: "4.17.20",
    },
    cwePriority: ["CWE-79", "CWE-352", "CWE-798", "CWE-1321", "CWE-400"],
    minCvss: 7.0,
  },
  {
    slug: "react-spa",
    name: "React SPA",
    catalogStatus: "launch",
    sortOrder: 6,
    ecosystem: "npm",
    osvEcosystem: "npm",
    osvPackages: [
      "react", "react-dom", "react-router", "react-router-dom",
      "axios", "create-react-app",
    ],
    nvdKeywords: ["react spa", "create react app", "react frontend"],
    ghsaEcosystem: "NPM",
    npmPackages: {
      react: "18.0.0",
      "react-dom": "18.0.0",
      "react-router-dom": "6.0.0",
      axios: "0.21.1",
      lodash: "4.17.20",
    },
    cwePriority: [
      "CWE-79", "CWE-798", "CWE-359", "CWE-116", "CWE-285", "CWE-1321",
    ],
    minCvss: 7.0,
  },
  // ── COMING SOON ────────────────────────────────────────────────────────
  {
    slug: "django",
    name: "Django",
    catalogStatus: "coming_soon",
    sortOrder: 7,
    ecosystem: "pypi",
    osvEcosystem: "PyPI",
    osvPackages: ["django", "djangorestframework", "django-cors-headers", "pillow"],
    nvdKeywords: ["django", "djangoproject"],
    ghsaEcosystem: "PIP",
    cwePriority: [
      "CWE-89", "CWE-284", "CWE-352", "CWE-530", "CWE-200", "CWE-798",
    ],
    minCvss: 7.0,
  },
  {
    slug: "rails",
    name: "Ruby on Rails",
    catalogStatus: "coming_soon",
    sortOrder: 8,
    ecosystem: "rubygems",
    osvEcosystem: "RubyGems",
    osvPackages: ["rails", "actionpack", "activerecord", "activesupport", "actionview"],
    nvdKeywords: ["ruby on rails", "rails framework"],
    ghsaEcosystem: "RUBYGEMS",
    cwePriority: [
      "CWE-915", "CWE-284", "CWE-352", "CWE-89", "CWE-79", "CWE-400",
    ],
    minCvss: 7.0,
  },
  {
    slug: "go",
    name: "Go",
    catalogStatus: "coming_soon",
    sortOrder: 9,
    ecosystem: "go",
    osvEcosystem: "Go",
    osvPackages: [
      "github.com/gin-gonic/gin",
      "github.com/golang-jwt/jwt",
      "gorm.io/gorm",
      "golang.org/x/net",
      "golang.org/x/crypto",
    ],
    nvdKeywords: ["gin-gonic", "golang web", "go net"],
    ghsaEcosystem: "GO",
    cwePriority: [
      "CWE-89", "CWE-22", "CWE-285", "CWE-798", "CWE-400", "CWE-295",
    ],
    minCvss: 7.0,
  },
  {
    slug: "ios",
    name: "iOS / Swift",
    catalogStatus: "coming_soon",
    sortOrder: 10,
    ecosystem: "swift",
    osvEcosystem: "SwiftURL",
    osvPackages: [
      "github.com/Alamofire/Alamofire",
      "github.com/realm/realm-swift",
    ],
    nvdKeywords: ["ios swift", "apple ios sdk", "swiftui"],
    ghsaEcosystem: "SWIFT",
    cwePriority: ["CWE-312", "CWE-295", "CWE-200", "CWE-798", "CWE-532"],
    minCvss: 6.5,
  },
  {
    slug: "android",
    name: "Android / Kotlin",
    catalogStatus: "coming_soon",
    sortOrder: 11,
    ecosystem: "maven",
    osvEcosystem: "Maven",
    osvPackages: [
      "com.squareup.okhttp3:okhttp",
      "com.google.firebase:firebase-auth",
      "androidx.security:security-crypto",
    ],
    nvdKeywords: ["android kotlin", "android sdk", "androidx"],
    ghsaEcosystem: "MAVEN",
    cwePriority: ["CWE-312", "CWE-295", "CWE-532", "CWE-798", "CWE-200"],
    minCvss: 6.5,
  },
];

export const LAUNCH_STACK_CONFIGS = STACK_REGISTRY.filter(
  s => s.catalogStatus === "launch"
);

export const COMING_SOON_STACK_CONFIGS = STACK_REGISTRY.filter(
  s => s.catalogStatus === "coming_soon"
);
