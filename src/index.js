/**
 * PDF XSS Checker
 * Main entry point for the package
 */
const fs = require('fs');
const path = require('path');
const { scanPdfBuffer } = require('./scanner');
const { generateReport } = require('./reporter');

const validateMagicBytes = (buffer, mode = 'full') => {
  const magic = '%PDF-';
  if (mode === 'strict') {
    return buffer.length >= 5 && buffer.toString('utf8', 0, 5) === magic;
  } else if (mode === 'standard') {
    const searchArea = buffer.subarray(0, Math.min(buffer.length, 1024)).toString('utf8');
    return searchArea.includes(magic);
  } else {
    return buffer.indexOf(Buffer.from(magic)) !== -1;
  }
};

/**
 * Scan a PDF file for XSS vulnerabilities
 * @param {string} filePath - Path to the PDF file
 * @param {Object} options - Scanning options
 * @returns {Promise<Object>} Scan results
 */
const scanPdf = async (filePath, options = {}) => {
  try {
    const pdfBuffer = await fs.promises.readFile(filePath);
    
    if (!validateMagicBytes(pdfBuffer, options.magicByteCheck)) {
      throw new Error('File must be a valid PDF');
    }
    
    const scanResults = await scanPdfBuffer(pdfBuffer, options);
    return generateReport(scanResults, { fileName: path.basename(filePath), ...options });
  } catch (error) {
    return {
      success: false,
      error: error.code === 'ENOENT' ? `File not found: ${filePath}` : error.message,
      vulnerabilities: [],
      safeToUse: false
    };
  }
};

/**
 * Scan a PDF buffer for XSS vulnerabilities
 * @param {Buffer} buffer - PDF file buffer
 * @param {Object} options - Scanning options
 * @returns {Promise<Object>} Scan results
 */
const scanBuffer = async (buffer, options = {}) => {
  try {
    if (!Buffer.isBuffer(buffer)) {
      throw new Error('Input must be a Buffer');
    }
    if (!validateMagicBytes(buffer, options.magicByteCheck)) {
      throw new Error('Buffer must contain a valid PDF');
    }
    const scanResults = await scanPdfBuffer(buffer, options);
    return generateReport(scanResults, { fileName: 'buffer', ...options });
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
 * Main API for the package
 */
module.exports = {
  scanPdf,
  scanBuffer,
  // Re-export utility functions
  utils: require('./utils')
};