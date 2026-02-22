const { detectXssPatterns } = require('./src/detectors/xssPatterns');
const { detectJsInjection } = require('./src/detectors/jsInjection');

const content = `<< /BaseFont /SNCSTG+CMBX12 /FontDescriptor 6 0 R /FontMatrix [ 1 2 3 4 5 (1); alert('origin: '+window.origin+', pdf url: '+(window.PDFViewerApplication?window.PDFViewerApplication.url:document.URL)) ] /Subtype /Type1 /Type /Font >>`;

const xss = detectXssPatterns(content, { threshold: 'medium' });
const js = detectJsInjection(content, { threshold: 'medium' });

console.log('XSS patterns found:');
xss.forEach(v => console.log(`  - ${v.name} (${v.severity}): ${v.matchedText}`));

console.log('\nJS injection patterns found:');
js.forEach(v => console.log(`  - ${v.name} (${v.severity}): ${v.matchedText}`));

console.log(`\nTotal vulnerabilities: ${xss.length + js.length}`);
