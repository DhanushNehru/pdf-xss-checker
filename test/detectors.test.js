/**
 * Detector tests
 */
const { detectXssPatterns } = require('../src/detectors/xssPatterns');
const { detectJsInjection } = require('../src/detectors/jsInjection');
const { detectFormInjection } = require('../src/detectors/formInjection');

describe('XSS Pattern Detector', () => {
  test('should detect script tags', () => {
    const content = 'This content has <script>alert("XSS")</script> embedded in it';
    const results = detectXssPatterns(content);
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name).toBe('Script Tag');
    expect(results[0].severity).toBe('high');
  });
  
  test('should detect javascript: protocol', () => {
    const content = 'This link is malicious: <a href="javascript:alert(1)">Click me</a>';
    const results = detectXssPatterns(content);
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name).toBe('JavaScript Protocol');
  });
  
  test('should detect event handlers', () => {
    const content = '<div onclick="alert(1)">Click me</div>';
    const results = detectXssPatterns(content);
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name).toBe('Event Handler');
  });
  
  test('should respect threshold settings', () => {
    const content = '<div onclick="alert(1)">Click me</div>';
    
    const lowResults = detectXssPatterns(content, { threshold: 'low' });
    const highResults = detectXssPatterns(content, { threshold: 'high' });
    
    expect(lowResults.length).toBeGreaterThan(0);
    expect(highResults.length).toBe(0); // 'Event Handler' is medium severity
  });
});

describe('JavaScript Injection Detector', () => {
  test('should detect Acrobat API calls', () => {
    const content = 'app.alert("This is an alert");';
    const results = detectJsInjection(content);
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name).toBe('Acrobat API Call');
  });
  
  test('should detect critical patterns', () => {
    const content = 'app.execMenuItem("MenuItem");';
    const results = detectJsInjection(content);
    
    expect(results.length).toBeGreaterThan(0);
    // Should find both Acrobat API Call and Execute Menu Item
    const executeMenuItem = results.find(r => r.name === 'Execute Menu Item');
    expect(executeMenuItem).toBeDefined();
    expect(executeMenuItem.severity).toBe('critical');
  });
  
  test('should include context in results', () => {
    const content = 'Some text before\napp.alert("This is an alert");\nSome text after';
    const results = detectJsInjection(content);
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].context).toContain('app.alert');
    expect(results[0].context.length).toBeGreaterThan(0);
  });
});

describe('Form Injection Detector', () => {
  test('should detect HTML forms', () => {
    const content = '<form action="https://example.com/submit">Form fields</form>';
    const results = detectFormInjection(content);
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name).toBe('HTML Form');
  });
  
  test('should detect form submission', () => {
    const content = 'form.submit();';
    const results = detectFormInjection(content);
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name).toBe('Form Submission');
  });
  
  test('should detect PDF form structures', () => {
    const content = '/AcroForm << /Fields [] >>';
    const results = detectFormInjection(content, { threshold: 'low' });
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].name).toBe('AcroForm Structure');
  });
  
  test('should truncate long matched text', () => {
    const longForm = '<form>' + 'x'.repeat(100) + '</form>';
    const results = detectFormInjection(longForm);
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].matchedText.length).toBeLessThan(100);
    expect(results[0].matchedText).toContain('...');
  });
});