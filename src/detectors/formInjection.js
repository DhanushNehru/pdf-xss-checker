/**
 * Form Injection Detector
 * Detects potential form-based injection vectors in PDF content
 */

/**
 * Form injection patterns
 */
const FORM_INJECTION_PATTERNS = [
  {
    pattern: /<form[\s\S]*?>[\s\S]*?<\/form>/gi,
    name: 'HTML Form',
    description: 'Found HTML form elements that may submit data',
    severity: 'medium'
  },
  {
    pattern: /submit\s*\(/gi,
    name: 'Form Submission',
    description: 'Found form submission calls',
    severity: 'medium'
  },
  {
    pattern: /FDF|XFDF/gi,
    name: 'Form Data Format',
    description: 'Found references to FDF/XFDF form data formats',
    severity: 'low'
  },
  {
    pattern: /\/AcroForm\s*<<\s*\/Fields/gi,
    name: 'AcroForm Structure',
    description: 'Found AcroForm dictionary structure',
    severity: 'low'
  },
  {
    pattern: /\/XFA/gi,
    name: 'XFA Form',
    description: 'Found XFA (XML Forms Architecture) references',
    severity: 'medium'
  },
  {
    pattern: /\/A\s*<<\s*\/S\s*\/SubmitForm/gi,
    name: 'Form Submit Action',
    description: 'Found form submission action in PDF',
    severity: 'high'
  }
];

const { calculateLineOffsets, getPositionFromOffset } = require('../utils');

/**
 * Detect form-based injection vectors in PDF content
 * @param {string} content - Extracted PDF text content
 * @param {Object} options - Detection options
 * @returns {Array} List of detected vulnerabilities
 */
const detectFormInjection = (content, options = {}) => {
  const vulnerabilities = [];
  const thresholds = {
    low: ['low', 'medium', 'high', 'critical'],
    medium: ['medium', 'high', 'critical'],
    high: ['high', 'critical'],
    critical: ['critical']
  };
  
  const severityFilter = thresholds[options.threshold || 'medium'];

  // Check for form-related patterns
  const patternsToCheck = FORM_INJECTION_PATTERNS.filter(pattern => 
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
        type: 'form-injection',
        name: patternDef.name,
        description: patternDef.description,
        severity: patternDef.severity,
        matchedText: matchedText.length > 50 ? `${matchedText.substring(0, 47)}...` : matchedText,
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
  detectFormInjection,
  FORM_INJECTION_PATTERNS
};