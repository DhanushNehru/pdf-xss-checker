/**
 * XSS Pattern Detector
 * Detects common XSS patterns in PDF content
 */

/**
 * XSS pattern definitions with severity levels
 */
const XSS_PATTERNS = [
  {
    pattern: /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
    name: 'Script Tag',
    description: 'Found <script> tags that may execute JavaScript',
    severity: 'high'
  },
  {
    pattern: /javascript\s*:/gi,
    name: 'JavaScript Protocol',
    description: 'Found javascript: protocol that may execute code',
    severity: 'high'
  },
  {
    pattern: /on(load|click|mouseover|mouse\w+|key\w+)\s*=\s*["']?[^"']*["']?/gi,
    name: 'Event Handler',
    description: 'Found event handlers that may execute JavaScript',
    severity: 'medium'
  },
  {
    pattern: /<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi,
    name: 'iFrame Element',
    description: 'Found <iframe> elements that may load malicious content',
    severity: 'high'
  },
  {
    pattern: /document\.write\s*\(/gi,
    name: 'Document Write',
    description: 'Found document.write() calls that may inject content',
    severity: 'medium'
  },
  {
    pattern: /eval\s*\(/gi,
    name: 'Eval Function',
    description: 'Found eval() calls that execute arbitrary code',
    severity: 'critical'
  },
  {
    pattern: /new\s+Function\s*\(/gi,
    name: 'Function Constructor',
    description: 'Found Function constructor that may execute arbitrary code',
    severity: 'critical'
  },
  {
    pattern: /set(Timeout|Interval)\s*\(/gi,
    name: 'Timer Functions',
    description: 'Found setTimeout or setInterval that may execute code',
    severity: 'medium'
  },
  {
    pattern: /\balert\s*\(/gi,
    name: 'Alert Call',
    description: 'Found alert() call that may indicate XSS payload execution',
    severity: 'high'
  },
  {
    pattern: /\b(confirm|prompt)\s*\(/gi,
    name: 'Browser Dialog Call',
    description: 'Found confirm() or prompt() call that may indicate XSS payload execution',
    severity: 'high'
  },
  {
    pattern: /\bwindow\s*\.\s*\w+/gi,
    name: 'Window Property Access',
    description: 'Found window.* property access that may indicate XSS (e.g. window.origin, window.location)',
    severity: 'high'
  },
  {
    pattern: /\bwindow\s*\[\s*['"][^'"]+['"]\s*\]/gi,
    name: 'Window Bracket Access',
    description: 'Found window["..."] bracket notation access that may indicate obfuscated XSS',
    severity: 'high'
  },
  {
    pattern: /\bdocument\s*\.\s*(URL|location|cookie|domain|referrer|documentURI)\b/gi,
    name: 'Document Property Access',
    description: 'Found access to sensitive document properties (URL, cookie, location, etc.)',
    severity: 'high'
  },
  {
    pattern: /\bdocument\s*\.\s*(createElement|createElementNS|execCommand)\s*\(/gi,
    name: 'Document DOM Manipulation',
    description: 'Found document DOM manipulation that may inject malicious elements',
    severity: 'medium'
  },
  {
    pattern: /\bPDFViewerApplication\b/gi,
    name: 'PDF Viewer Application Access',
    description: 'Found reference to PDFViewerApplication (PDF.js viewer object), commonly targeted in PDF XSS attacks',
    severity: 'critical'
  },
  {
    pattern: /\blocation\s*\.\s*(href|assign|replace|hash|search|pathname)\b/gi,
    name: 'Location Manipulation',
    description: 'Found location property access that may redirect or leak data',
    severity: 'high'
  },
  {
    pattern: /\b(fetch|XMLHttpRequest|ActiveXObject)\s*\(/gi,
    name: 'Network Request',
    description: 'Found network request API calls that may exfiltrate data',
    severity: 'high'
  },
  {
    pattern: /\bnavigator\s*\.\s*\w+/gi,
    name: 'Navigator Access',
    description: 'Found navigator property access that may fingerprint or exfiltrate browser info',
    severity: 'medium'
  },
  {
    pattern: /\bpostMessage\s*\(/gi,
    name: 'PostMessage Call',
    description: 'Found postMessage() call that may communicate with parent/opener windows',
    severity: 'medium'
  }
];

const { calculateLineOffsets, getPositionFromOffset } = require('../utils');

/**
 * Detect XSS patterns in the extracted PDF text
 * @param {string} content - Extracted PDF text content
 * @param {Object} options - Detection options
 * @returns {Array} List of detected vulnerabilities
 */
const detectXssPatterns = (content, options = {}) => {
  const vulnerabilities = [];
  const thresholds = {
    low: ['low', 'medium', 'high', 'critical'],
    medium: ['medium', 'high', 'critical'],
    high: ['high', 'critical'],
    critical: ['critical']
  };
  
  const severityFilter = thresholds[options.threshold || 'medium'];

  // Filter patterns based on severity threshold
  const patternsToCheck = XSS_PATTERNS.filter(pattern => 
    severityFilter.includes(pattern.severity)
  );

  const lineOffsets = options.lineOffsets || calculateLineOffsets(content);

  // Check each pattern against the content
  patternsToCheck.forEach(patternDef => {
    const matches = [...content.matchAll(patternDef.pattern)];
    
    matches.forEach(match => {
      const matchedText = match[0];
      const startIndex = match.index;
      const endIndex = startIndex + matchedText.length;
      
      // Calculate line and column positions (approximate)
      const { line: lineNumber, column: columnNumber } = getPositionFromOffset(lineOffsets, startIndex);
      
      // Get context (text before and after the match)
      const contextStart = Math.max(0, startIndex - 20);
      const contextEnd = Math.min(content.length, endIndex + 20);
      const context = content.substring(contextStart, contextEnd);
      
      vulnerabilities.push({
        type: 'xss',
        name: patternDef.name,
        description: patternDef.description,
        severity: patternDef.severity,
        matchedText: matchedText,
        location: {
          startIndex,
          endIndex,
          line: lineNumber,
          column: columnNumber
        },
        context: context.trim()
      });
    });
  });

  return vulnerabilities;
};

module.exports = {
  detectXssPatterns,
  XSS_PATTERNS
};