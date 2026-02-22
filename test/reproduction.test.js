
const { scanPdfBuffer } = require('../src/scanner');

// Mock pdf-parse
jest.mock('pdf-parse', () => {
    return jest.fn().mockImplementation(() => {
        return Promise.resolve({
            numpages: 1,
            info: {},
            metadata: null,
            text: ''
        });
    });
});

describe('SOC 2 PDF XSS - FontMatrix injection', () => {
    test('should detect alert() in FontMatrix payload', async () => {
        const maliciousContent = `5 0 obj\n<< /BaseFont /SNCSTG+CMBX12 /FontDescriptor 6 0 R /FontMatrix [ 1 2 3 4 5 (1); alert('origin: '+window.origin+', pdf url: '+(window.PDFViewerApplication?window.PDFViewerApplication.url:document.URL)) ] /Subtype /Type1 /Type /Font >>\nendobj`;
        const buffer = Buffer.from(maliciousContent);
        
        const results = await scanPdfBuffer(buffer);

        console.log('Vulnerabilities found:', results.vulnerabilities.map(v => `${v.name} (${v.severity})`));

        // Should detect alert()
        const alertVuln = results.vulnerabilities.find(v => v.name === 'Alert Call');
        expect(alertVuln).toBeDefined();

        // Should detect window.origin / window.PDFViewerApplication
        const windowVuln = results.vulnerabilities.find(v => v.name === 'Window Property Access');
        expect(windowVuln).toBeDefined();

        // Should detect PDFViewerApplication
        const pdfViewerVuln = results.vulnerabilities.find(v => v.name === 'PDF Viewer Application Access');
        expect(pdfViewerVuln).toBeDefined();

        // Should detect document.URL
        const docVuln = results.vulnerabilities.find(v => v.name === 'Document Property Access');
        expect(docVuln).toBeDefined();

        // Overall: not safe
        expect(results.safeToUse).toBe(false);
    });

    test('should not false-positive on normal FontMatrix', async () => {
        const safeContent = `5 0 obj\n<< /BaseFont /SNCSTG+CMBX12 /FontDescriptor 6 0 R /FontMatrix [ 0.001 0 0 0.001 0 0 ] /Subtype /Type1 /Type /Font >>\nendobj`;
        const buffer = Buffer.from(safeContent);
        
        const results = await scanPdfBuffer(buffer);

        const xssVulns = results.vulnerabilities.filter(v => 
            v.name === 'Alert Call' || 
            v.name === 'Window Property Access' || 
            v.name === 'PDF Viewer Application Access' ||
            v.name === 'Document Property Access'
        );
        expect(xssVulns.length).toBe(0);
    });
});
