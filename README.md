# PDF XSS Checker

[![npm version](https://img.shields.io/npm/v/pdf-xss-checker.svg?color=blue)](https://www.npmjs.com/package/pdf-xss-checker)

A Node.js package to verify if PDFs contain XSS (Cross-Site Scripting) vulnerabilities.

## Installation

```bash
npm install pdf-xss-checker
```

## Features

- **PDF Content Extraction**: Extracts and analyzes text content from PDF files
- **XSS Detection**: Identifies potential XSS vulnerabilities using pattern matching
- **JavaScript Injection Detection**: Detects JavaScript code that could lead to security issues
- **Form Injection Detection**: Identifies form-based attack vectors
- **Simple API**: Easy-to-use API for both file and buffer inputs
- **Detailed Reporting**: Comprehensive vulnerability reports with location information
- **Command-line Interface**: Scan PDFs directly from the terminal
- **Configurable Security Rules**: Adjust detection thresholds based on your security needs

## Usage

### API Usage

```javascript
const pdfXssChecker = require('pdf-xss-checker');

// Scan a PDF file
async function checkPdf() {
  try {
    const results = await pdfXssChecker.scanPdf('./document.pdf');
    
    if (results.success) {
      console.log(`Safe to use: ${results.safeToUse ? 'Yes' : 'No'}`);
      console.log(`Found ${results.vulnerabilities.length} potential vulnerabilities`);
      
      // Print vulnerabilities
      results.vulnerabilities.forEach(vuln => {
        console.log(`- ${vuln.name}: ${vuln.description} (${vuln.severity})`);
      });
    } else {
      console.error(`Error: ${results.error}`);
    }
  } catch (error) {
    console.error('Error scanning PDF:', error);
  }
}

// Scan a PDF buffer
async function checkBuffer(buffer) {
  try {
    const results = await pdfXssChecker.scanBuffer(buffer);
    console.log(`PDF is safe to use: ${results.safeToUse}`);
    return results;
  } catch (error) {
    console.error('Error scanning buffer:', error);
  }
}
```

### Advanced Options

```javascript
const options = {
  threshold: 'medium', // Severity threshold: 'low', 'medium', 'high', 'critical'
  detectors: ['xss', 'js', 'form'], // Which detectors to use
  includeRawContent: false, // Include raw PDF content in results
  maxContentLength: 10000000 // Maximum content length to analyze (10MB)
};

const results = await pdfXssChecker.scanPdf('./document.pdf', options);
```

### Command-line Usage

```bash
# Basic usage
npx pdf-xss-check document.pdf

# With options
npx pdf-xss-check document.pdf --threshold low --verbose --output results.json

# Help
npx pdf-xss-check --help
```

## CLI Options

```
Usage: pdf-xss-check [options] <file>

Check PDF files for XSS vulnerabilities

Arguments:
  file                     PDF file to scan

Options:
  -V, --version            output the version number
  -t, --threshold <level>  Detection threshold (low, medium, high, critical) (default: "medium")
  -v, --verbose           Show detailed output (default: false)
  -j, --json              Output results as JSON (default: false)
  -o, --output <file>     Write results to file
  --include-content       Include raw content in the report (may be large) (default: false)
  --include-grouped       Include grouped vulnerabilities in the report (default: false)
  -h, --help             display help for command
```

## Detection Patterns

The package checks for various XSS and injection patterns, including:

- Script tags (`<script>`)
- JavaScript protocol usage (`javascript:`)
- Event handlers (`onclick`, etc.)
- iFrame elements
- Document manipulation functions
- JavaScript execution functions (`eval`, etc.)
- Form injection vectors
- PDF-specific JavaScript API calls

## Results Format

The scan results include:

```javascript
{
  success: true,
  summary: {
    fileName: 'document.pdf',
    timestamp: '2025-01-01T12:00:00.000Z',
    pageCount: 5,
    vulnerabilityCount: 3,
    riskLevel: 'medium',
    safeToUse: false,
    severityCounts: { medium: 2, high: 1 },
    typeCounts: { xss: 2, 'js-injection': 1 }
  },
  metadata: {
    info: { /* PDF metadata */ },
    pageCount: 5,
    contentLength: 12345
  },
  vulnerabilities: [
    {
      type: 'xss',
      name: 'Script Tag',
      description: 'Found <script> tags that may execute JavaScript',
      severity: 'high',
      matchedText: '<script>alert("XSS")</script>',
      location: {
        startIndex: 1234,
        endIndex: 1260,
        line: 42,
        column: 10
      },
      context: '...text before <script>alert("XSS")</script> text after...'
    },
    // More vulnerabilities...
  ]
}
```
## Run with Docker
1️⃣ Build the Docker image
docker build -t pdf-xss-checker-example -f docker/Dockerfile .

2️⃣ Generate sample PDFs

If not already generated, create the example PDFs:
npm install
npm run generate-samples

This will create two files:

1. examples/sample1.pdf → clean PDF

2. examples/sample2.pdf → contains a sample XSS payload

3️⃣ Run the scanner on the sample PDFs
For Linux / macOS

Use $(pwd) to mount the current folder:

docker run --rm -v "$(pwd)/examples:/examples" pdf-xss-checker-example node src/index.js /examples/sample1.pdf
docker run --rm -v "$(pwd)/examples:/examples" pdf-xss-checker-example node src/index.js /examples/sample2.pdf

🪟 Windows PowerShell

Use ${PWD} for the current directory:

docker run --rm -v "${PWD}\examples:/examples" pdf-xss-checker-example node src/index.js /examples/sample1.pdf
docker run --rm -v "${PWD}\examples:/examples" pdf-xss-checker-example node src/index.js /examples/sample2.pdf

🪟 Windows CMD

Use %cd%:

docker run --rm -v "%cd%\examples:/examples" pdf-xss-checker-example node src/index.js /examples/sample1.pdf
docker run --rm -v "%cd%\examples:/examples" pdf-xss-checker-example node src/index.js /examples/sample2.pdf

✅ Expected Output
Scanning /examples/sample1.pdf ...
✅ No XSS detected

Scanning /examples/sample2.pdf ...
⚠️ Potential XSS detected: <script>alert('XSS')</script>


## License

MIT
