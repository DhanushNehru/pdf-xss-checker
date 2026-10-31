/**
 * Serialize pdf-parse calls within this JavaScript isolate.
 *
 * pdf-parse uses shared parser state and must not be entered concurrently.
 * Each worker thread has its own module instance, while this queue also
 * protects the synchronous scanner path used by tests and direct callers.
 */
const pdfParse = require('pdf-parse');

let parseQueue = Promise.resolve();

const parsePdf = (buffer, options) => {
  const result = parseQueue.then(() => pdfParse(buffer, options));
  parseQueue = result.then(() => undefined, () => undefined);
  return result;
};

module.exports = parsePdf;
