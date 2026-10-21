// Vercel serverless entry. vercel.json rewrites /api/:path* here; Express sees the full path.
import { createApp } from './_lib/app.js';

const app = createApp();

export default function handler(req, res) {
  return app(req, res);
}
