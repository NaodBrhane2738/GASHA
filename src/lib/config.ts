export const deepSeekConfig = {
  apiKey:
    process.env.DEEPSEEK_API_KEY ??
    process.env.NEXT_PUBLIC_DEEPSEEK_API_KEY ??
    "",
  baseUrl: process.env.DEEPSEEK_API_BASE_URL ?? "https://api.deepseek.com",
};
