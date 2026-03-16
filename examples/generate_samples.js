// examples/generate_samples.js
const PDFDocument = require("pdfkit");
const fs = require("fs");

function createPDF(filename, text) {
  const doc = new PDFDocument();
  doc.pipe(fs.createWriteStream(filename));
  doc.text(text);
  doc.end();
}

createPDF("examples/sample1.pdf", "Normal PDF content");
createPDF("examples/sample2.pdf", "<script>alert('XSS');</script>");
console.log("✅ Sample PDFs generated in /examples folder");
