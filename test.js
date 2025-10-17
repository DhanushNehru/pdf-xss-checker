const fs = require('fs');
const pdfXssScanner = require('./src/index');

// Create a simple PDF buffer with potential XSS content
const maliciousPdfContent = Buffer.from('%PDF-1.7\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>/Contents 4 0 R>>\nendobj\n4 0 obj\n<</Length 100>>\nstream\nBT\n/F1 12 Tf\n72 712 Td\n(<script>alert("xss")</script>) Tj\nET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f\n0000000010 00000 n\n0000000056 00000 n\n0000000111 00000 n\n0000000212 00000 n\ntrailer\n<</Size 5/Root 1 0 R>>\nstartxref\n321\n%%EOF');

// Create a clean PDF buffer
const cleanPdfContent = Buffer.from('%PDF-1.7\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>/Contents 4 0 R>>\nendobj\n4 0 obj\n<</Length 50>>\nstream\nBT\n/F1 12 Tf\n72 712 Td\n(Hello World) Tj\nET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f\n0000000010 00000 n\n0000000056 00000 n\n0000000111 00000 n\n0000000212 00000 n\ntrailer\n<</Size 5/Root 1 0 R>>\nstartxref\n321\n%%EOF');

async function runTests() {
    console.log('Testing PDF XSS Scanner...\n');

    // Test 1: Malicious PDF
    console.log('Test 1: Scanning malicious PDF');
    const result1 = await pdfXssScanner.scanBuffer(maliciousPdfContent);
    console.log('Result object:', JSON.stringify(result1, null, 2));
    console.log('Result:', result1.vulnerabilities && result1.vulnerabilities.length > 0 ? 'XSS DETECTED ❌' : 'NO XSS DETECTED ✅');
    if (result1.vulnerabilities && result1.vulnerabilities.length > 0) {
        console.log('Vulnerabilities found:', result1.vulnerabilities.length);
    }

    // Test 2: Clean PDF
    console.log('\nTest 2: Scanning clean PDF');
    const result2 = await pdfXssScanner.scanBuffer(cleanPdfContent);
    console.log('Result:', result2.vulnerabilities && result2.vulnerabilities.length > 0 ? 'XSS DETECTED ❌' : 'NO XSS DETECTED ✅');
    if (result2.vulnerabilities && result2.vulnerabilities.length > 0) {
        console.log('Vulnerabilities found:', result2.vulnerabilities.length);
    }
}

runTests().catch(console.error);