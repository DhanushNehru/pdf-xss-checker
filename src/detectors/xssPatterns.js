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
  }
];

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

  // Check each pattern against the content
  patternsToCheck.forEach(patternDef => {
    const matches = [...content.matchAll(patternDef.pattern)];
    
    matches.forEach(match => {
      const matchedText = match[0];
      const startIndex = match.index;
      const endIndex = startIndex + matchedText.length;
      
      // Calculate line and column positions (approximate)
      const contentBeforeMatch = content.substring(0, startIndex);
      const lines = contentBeforeMatch.split('\n');
      const lineNumber = lines.length;
      const columnNumber = lines[lines.length - 1].length + 1;
      
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