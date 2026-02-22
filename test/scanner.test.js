/**
 * Scanner tests
 */
const fs = require('fs');
const path = require('path');
const { scanPdfBuffer } = require('../src/scanner');

// Mock pdf-parse since we can't actually parse PDFs in tests
jest.mock('pdf-parse', () => {
  return jest.fn().mockImplementation((buffer, options) => {
    // Return mock data based on the buffer content
    const isMalicious = buffer.toString().includes('malicious');
    
    return Promise.resolve({
      numpages: 5,
      info: {
        Creator: 'Test',
        Producer: 'Jest Test',
        CreationDate: new Date().toString()
      },
      metadata: null,
      text: isMalicious ? 
        '<script>alert("XSS")</script>\njavascript:alert(1)\ndocument.write("<iframe src=javascript:alert(1)></iframe>")\neval("alert(1)")' :
        'This is a safe PDF document with no malicious content.'
    });
  });
});

describe('PDF Scanner', () => {
  test('should detect XSS vulnerabilities in malicious PDF', async () => {
    // Create a mock buffer with "malicious" flag
    const buffer = Buffer.from('malicious pdf content');
    
    const results = await scanPdfBuffer(buffer);
    
    expect(results.success).toBe(true);
    expect(results.safeToUse).toBe(false);
    expect(results.vulnerabilities.length).toBeGreaterThan(0);
    expect(results.riskLevel).not.toBe('none');
    
    // Check for specific vulnerability types
    const vulnTypes = results.vulnerabilities.map(v => v.name);
    expect(vulnTypes).toContain('Script Tag');
    expect(vulnTypes).toContain('JavaScript Protocol');
  });
  
  test('should report safe for clean PDF', async () => {
    // Create a mock buffer without "malicious" flag
    const buffer = Buffer.from('clean pdf content');
    
    const results = await scanPdfBuffer(buffer);
    
    expect(results.success).toBe(true);
    expect(results.safeToUse).toBe(true);
    expect(results.vulnerabilities).toHaveLength(0);
    expect(results.riskLevel).toBe('none');
  });
  
  test('should respect threshold settings', async () => {
    // Create a mock buffer with "malicious" flag
    const buffer = Buffer.from('malicious pdf content');
    
    // Test with high threshold
    const highResults = await scanPdfBuffer(buffer, { threshold: 'high' });
    
    // Test with low threshold
    const lowResults = await scanPdfBuffer(buffer, { threshold: 'low' });
    
    // Low threshold should find more vulnerabilities
    expect(lowResults.vulnerabilities.length).toBeGreaterThanOrEqual(highResults.vulnerabilities.length);
  });
  
  test('should handle errors gracefully', async () => {
    // Pass null to trigger an error in the buffer check
    const results = await scanPdfBuffer(null);
    
    expect(results.success).toBe(false);
    expect(results.error).toBeTruthy();
    expect(results.safeToUse).toBe(false);
  });
  
  test('should calculate risk level correctly', async () => {
    // Create mock buffers with different severity patterns
    const criticalBuffer = Buffer.from('malicious pdf content with eval("bad code")');
    const highBuffer = Buffer.from('malicious pdf content with <script>alert(1)</script>');
    const mediumBuffer = Buffer.from('malicious pdf content with onclick="void(0)"');
    
    // Mock different responses based on content
    require('pdf-parse').mockImplementation((buffer) => {
      const content = buffer.toString();
      let text = '';
      
      if (content.includes('eval')) {
        text = 'eval("bad code")';
      } else if (content.includes('<script>')) {
        text = '<script>alert(1)</script>';
      } else if (content.includes('onclick')) {
        text = '<div onclick="void(0)">Click me</div>';
      }
      
      return Promise.resolve({
        numpages: 5,
        info: {},
        text
      });
    });
    
    const criticalResults = await scanPdfBuffer(criticalBuffer);
    const highResults = await scanPdfBuffer(highBuffer);
    const mediumResults = await scanPdfBuffer(mediumBuffer);
    
    expect(criticalResults.riskLevel).toBe('critical');
    expect(highResults.riskLevel).toBe('high');
    expect(mediumResults.riskLevel).toBe('medium');
  });
});