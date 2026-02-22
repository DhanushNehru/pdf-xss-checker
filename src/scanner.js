/**
 * PDF XSS Scanner
 * Scans PDF content for XSS vulnerabilities
 */
const pdfParse = require('pdf-parse');
const { detectXssPatterns } = require('./detectors/xssPatterns');
const { detectJsInjection } = require('./detectors/jsInjection');
const { detectFormInjection } = require('./detectors/formInjection');
const { calculateLineOffsets } = require('./utils');
const workerPool = require('./workerPool');

/**
 * Scan a PDF buffer for XSS vulnerabilities
 * @param {Buffer} pdfBuffer - PDF file buffer
 * @param {Object} options - Scanning options
 * @returns {Promise<Object>} Scan results
 */
const scanPdfBuffer = async (pdfBuffer, options = {}) => {
  // If running in test environment, use synchronous execution
  // This is required because Jest mocks (like pdf-parse) don't propagate to worker threads
  if (process.env.NODE_ENV === 'test' || process.env.JEST_WORKER_ID) {
    return scanPdfBufferSync(pdfBuffer, options);
  }

  try {
    if (!pdfBuffer) {
      throw new Error('PDF buffer is required');
    }
    return await workerPool.runTask(pdfBuffer, options);
  } catch (error) {
    return {
      success: false,
      error: error.message,
      vulnerabilities: [],
      safeToUse: false
    };
  }
};

/**
 * Synchronous scan implementation
 * Used for testing or when workers are disabled
 */
const scanPdfBufferSync = async (pdfBuffer, options = {}) => {
  try {
    if (!pdfBuffer) {
      throw new Error('PDF buffer is required');
    }

    // Set default options
    const scanOptions = {
      maxContentLength: options.maxContentLength || 10000000, // 10MB
      detectors: options.detectors || ['xss', 'js', 'form'],
      threshold: options.threshold || 'medium',
      ...options
    };

    // Parse the PDF
    let data;
    try {
      data = await pdfParse(pdfBuffer, {
        max: scanOptions.maxContentLength
      });
    } catch (parseError) {
      // If parsing fails, we still want to scan the raw buffer
      data = {
        info: {},
        numpages: 0,
        text: ''
      };
    }

    // Convert buffer to string for raw scanning (careful with large buffers)
    const rawContent = pdfBuffer ? pdfBuffer.toString('binary') : '';

    // Combine extracted text and raw content for comprehensive scanning
    const contentToScan = data.text + '\n---RAW_PDF_CONTENT---\n' + rawContent;

    // Pre-calculate line offsets once for all detectors
    const lineOffsets = calculateLineOffsets(contentToScan);
    scanOptions.lineOffsets = lineOffsets;

    // Initialize scan results
    const scanResults = {
      success: true,
      metadata: {
        info: data.info,
        pageCount: data.numpages,
        contentLength: contentToScan.length
      },
      vulnerabilities: [],
      rawContent: scanOptions.includeRawContent ? contentToScan : undefined
    };

    // Run enabled detectors
    if (scanOptions.detectors.includes('xss')) {
      const xssVulnerabilities = detectXssPatterns(contentToScan, scanOptions);
      scanResults.vulnerabilities.push(...xssVulnerabilities);
    }

    if (scanOptions.detectors.includes('js')) {
      const jsVulnerabilities = detectJsInjection(contentToScan, scanOptions);
      scanResults.vulnerabilities.push(...jsVulnerabilities);
    }

    if (scanOptions.detectors.includes('form')) {
      const formVulnerabilities = detectFormInjection(contentToScan, scanOptions);
      scanResults.vulnerabilities.push(...formVulnerabilities);
    }

    // Calculate overall safety
    scanResults.safeToUse = scanResults.vulnerabilities.length === 0;
    scanResults.riskLevel = calculateRiskLevel(scanResults.vulnerabilities);

    return scanResults;
  } catch (error) {
    return {
      success: false,
      error: error.message,
      vulnerabilities: [],
      safeToUse: false
    };
  }
};

/**
 * Calculate the risk level based on vulnerabilities
 * @param {Array} vulnerabilities - List of vulnerabilities
 * @returns {string} Risk level (low, medium, high, critical)
 */
const calculateRiskLevel = (vulnerabilities) => {
  if (vulnerabilities.length === 0) return 'none';
  
  const severityCounts = vulnerabilities.reduce((counts, vuln) => {
    counts[vuln.severity] = (counts[vuln.severity] || 0) + 1;
    return counts;
  }, {});
  
  if (severityCounts.critical > 0) return 'critical';
  if (severityCounts.high > 0) return 'high';
  if (severityCounts.medium > 0) return 'medium';
  return 'low';
};


module.exports = {
  scanPdfBuffer
};