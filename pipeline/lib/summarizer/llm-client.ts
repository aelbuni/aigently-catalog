import Anthropic from "@anthropic-ai/sdk";
import AnthropicBedrock from "@anthropic-ai/bedrock-sdk";

const BEDROCK_MODEL_IDS: Record<string, string> = {
  "claude-sonnet-4-6":             "us.anthropic.claude-sonnet-4-6",
  "claude-opus-4-7":               "us.anthropic.claude-opus-4-7",
  "claude-haiku-4-5-20251001":     "us.anthropic.claude-haiku-4-5-20251001-v1:0",
};

const TASK_DEFAULT_MODELS: Record<string, string> = {
  threat_amplification:    "claude-haiku-4-5-20251001",
  guardrail_summarization: "claude-sonnet-4-6",
  rule_summarization:      "claude-sonnet-4-6",
};

function detectProvider(): "bedrock" | "anthropic" {
  return process.env.AWS_REGION &&
    process.env.AWS_ACCESS_KEY_ID &&
    process.env.AWS_SECRET_ACCESS_KEY
    ? "bedrock"
    : "anthropic";
}

function toBedrockModelId(model: string): string {
  return BEDROCK_MODEL_IDS[model] ?? `us.anthropic.${model}`;
}

export function createLLMClient(): Anthropic {
  const provider = detectProvider();
  if (
    provider === "bedrock" &&
    process.env.AWS_REGION &&
    process.env.AWS_ACCESS_KEY_ID &&
    process.env.AWS_SECRET_ACCESS_KEY
  ) {
    return new AnthropicBedrock({
      awsRegion: process.env.AWS_REGION,
      awsAccessKey: process.env.AWS_ACCESS_KEY_ID,
      awsSecretKey: process.env.AWS_SECRET_ACCESS_KEY,
      awsSessionToken: process.env.AWS_SESSION_TOKEN ?? undefined,
    }) as unknown as Anthropic;
  }
  return new Anthropic();
}

export function getModelForTask(task: string): string {
  const envKey = `LLM_MODEL_${task.toUpperCase().replace(/-/g, "_")}`;
  const model =
    process.env[envKey] ??
    TASK_DEFAULT_MODELS[task] ??
    (process.env.FEATURE_CERTIFIED_SUMMARIES === "true" ? "claude-opus-4-7" : "claude-sonnet-4-6");

  return detectProvider() === "bedrock" ? toBedrockModelId(model) : model;
}
