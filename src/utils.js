/**
 * PDF XSS Scanner Utilities
 * Helper functions for the PDF XSS scanner
 */

/**
 * Get severity level as a numeric value
 * @param {string} severity - Severity level name
 * @returns {number} Numeric severity level
 */
const getSeverityLevel = (severity) => {
  const levels = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4
  };
  return levels[severity] || 0;
};

/**
 * Format size in bytes to human-readable string
 * @param {number} bytes - Size in bytes
 * @returns {string} Formatted size string
 */
const formatSize = (bytes) => {
  if (bytes < 1024) return bytes + ' bytes';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
};

/**
 * Truncate text to a specified length
 * @param {string} text - Input text
 * @param {number} maxLength - Maximum length
 * @returns {string} Truncated text
 */
const truncateText = (text, maxLength = 100) => {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
};

/**
 * Get all patterns from all detectors
 * @returns {Array} Combined patterns from all detectors
 */
const getAllPatterns = () => {
  const { XSS_PATTERNS } = require('./detectors/xssPatterns');
  const { JS_INJECTION_PATTERNS } = require('./detectors/jsInjection');
  const { FORM_INJECTION_PATTERNS } = require('./detectors/formInjection');
  
  return [
    ...XSS_PATTERNS,
    ...JS_INJECTION_PATTERNS,
    ...FORM_INJECTION_PATTERNS
  ];
};

/**
 * Check if a pattern matches in the content
 * @param {RegExp} pattern - Regular expression pattern
 * @param {string} content - Content to check
 * @returns {boolean} Whether pattern matches
 */
const hasPattern = (pattern, content) => {
  // Clone the regex to avoid mutating lastIndex on the original pattern
  const safePattern = new RegExp(pattern.source, pattern.flags);
  return safePattern.test(content);
};

/**
 * Pre-calculate line offsets for fast line/column lookups
 * @param {string} content - The text content
 * @returns {number[]} Array of indices where newlines occur
 */
const calculateLineOffsets = (content) => {
  const offsets = [0]; // First line starts at index 0
  for (let i = 0; i < content.length; i++) {
    if (content[i] === '\n') {
      offsets.push(i + 1);
    }
  }
  return offsets;
};

/**
 * Get line and column number from a character index using binary search
 * @param {number[]} offsets - Array of newline indices from calculateLineOffsets
 * @param {number} index - The character index to look up
 * @returns {Object} Object containing line and column (1-based)
 */
const getPositionFromOffset = (offsets, index) => {
  let low = 0;
  let high = offsets.length - 1;
  
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    if (offsets[mid] <= index) {
      if (mid === offsets.length - 1 || offsets[mid + 1] > index) {
        return {
          line: mid + 1,
          column: index - offsets[mid] + 1
        };
      }
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  
  return { line: 1, column: index + 1 };
};

module.exports = {
  getSeverityLevel,
  formatSize,
  truncateText,
  getAllPatterns,
  hasPattern,
  calculateLineOffsets,
  getPositionFromOffset
};