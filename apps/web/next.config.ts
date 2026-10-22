import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Required by apps/web/Dockerfile (copies .next/standalone).
  output: "standalone",
  async rewrites() {
    const backendUrl = process.env.BACKEND_URL || process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:4000";
    return [
      {
        source: "/api/v1/:path*",
        destination: `${backendUrl}/api/v1/:path*`,
      },
    ];
  },
};

export default nextConfig;
