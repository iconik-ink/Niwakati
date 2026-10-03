export class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// Express 4 doesn't catch rejected promises; this forwards them to the error handler.
export const h = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

export const maskEmail = (email) => {
  const [local, domain] = String(email).split('@');
  return `${local.slice(0, 1)}***@${domain}`;
};

// Pagination with a hard cap so a reviewer can't bulk-scrape through the API.
export function pageParams(req, maxLimit = 50) {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(maxLimit, Math.max(1, parseInt(req.query.limit, 10) || 20));
  return { limit, offset: (page - 1) * limit, page };
}
