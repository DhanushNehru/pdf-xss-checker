/**
 * JavaScript Injection Detector
 * Detects potential JavaScript injection in PDF content
 */

/**
 * JavaScript injection patterns
 */
const JS_INJECTION_PATTERNS = [
  {
    pattern: /app\.(\w+)\s*\(/gi,
    name: 'Acrobat API Call',
    description: 'Found calls to Acrobat JavaScript API',
    severity: 'high'
  },
  {
    pattern: /this\.(\w+)\s*\(/gi,
    name: 'PDF Object Method Call',
    description: 'Found calls to PDF object methods',
    severity: 'medium'
  },
  {
    pattern: /\bgetField\s*\(/gi,
    name: 'Form Field Access',
    description: 'Found attempts to access form fields',
    severity: 'medium'
  },
  {
    pattern: /\bapp\.alert\s*\(/gi,
    name: 'Alert Dialog',
    description: 'Found alert dialog calls',
    severity: 'low'
  },
  {
    pattern: /\bapp\.execMenuItem\s*\(/gi,
    name: 'Execute Menu Item',
    description: 'Found attempts to execute menu commands',
    severity: 'critical'
  },
  {
    pattern: /\bspawn\s*\(/gi,
    name: 'Process Spawn',
    description: 'Found attempts to spawn processes',
    severity: 'critical'
  },
  {
    pattern: /\bshell\s*\.\s*\w+/gi,
    name: 'Shell Command',
    description: 'Found potential shell command execution',
    severity: 'critical'
  },
  {
    pattern: /\/JavaScript/gi,
    name: 'PDF JavaScript Dictionary',
    description: 'Found /JavaScript dictionary which indicates embedded scripts',
    severity: 'high'
  },
  {
    pattern: /\/JS\s*(?:<|\[|\()/gi,
    name: 'PDF JS Entry',
    description: 'Found /JS entry which contains JavaScript code',
    severity: 'high'
  },
  {
    pattern: /\/OpenAction/gi,
    name: 'PDF OpenAction',
    description: 'Found /OpenAction which can execute scripts on open',
    severity: 'medium'
  },
  {
    pattern: /\/AA\s*<</gi,
    name: 'PDF Additional Actions',
    description: 'Found /AA (Additional Actions) which can execute scripts on events',
    severity: 'medium'
  },
  {
    pattern: /\/URI\s*\([^)]*javascript:/gi,
    name: 'PDF JavaScript URI',
    description: 'Found javascript: URI in PDF link',
    severity: 'high'
  },
  {
    pattern: /\/Launch/gi,
    name: 'PDF Launch Action',
    description: 'Found /Launch action which can execute external programs',
    severity: 'critical'
  },
  {
    pattern: /\/RichMedia/gi,
    name: 'PDF RichMedia',
    description: 'Found /RichMedia which can contain Flash or other executable content',
    severity: 'high'
  },
  {
    pattern: /\/FontMatrix\s*\[[\s\S]*?\([^\[\]]*[;)]/gi,
    name: 'FontMatrix JavaScript Injection',
    description: 'Found potential JavaScript injection in FontMatrix array (CVE-2024-4367)',
    severity: 'critical'
  }
];

const { calculateLineOffsets, getPositionFromOffset } = require('../utils');

/**
 * Detect JavaScript injection in PDF content
 * @param {string} content - Extracted PDF text content
 * @param {Object} options - Detection options
 * @returns {Array} List of detected vulnerabilities
 */
const detectJsInjection = (content, options = {}) => {
  const vulnerabilities = [];
  const thresholds = {
    low: ['low', 'medium', 'high', 'critical'],
    medium: ['medium', 'high', 'critical'],
    high: ['high', 'critical'],
    critical: ['critical']
  };
  
  const severityFilter = thresholds[options.threshold || 'medium'];

  // Check for JavaScript object notation
  const patternsToCheck = JS_INJECTION_PATTERNS.filter(pattern => 
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
        type: 'js-injection',
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
  detectJsInjection,
  JS_INJECTION_PATTERNS
};