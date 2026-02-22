#!/usr/bin/env node

/**
 * PDF XSS Checker CLI
 * Command-line interface for the PDF XSS scanner
 */
const fs = require('fs');
const path = require('path');
const { program } = require('commander');
const chalk = require('chalk');
const ora = require('ora');
const { scanPdf } = require('../src/index');
const package = require('../package.json');

// Configure the CLI
program
  .name('pdf-xss-check')
  .description('Check PDF files for XSS vulnerabilities')
  .version(package.version)
  .argument('<file>', 'PDF file to scan')
  .option('-t, --threshold <level>', 'Detection threshold (low, medium, high, critical)', 'medium')
  .option('-v, --verbose', 'Show detailed output', false)
  .option('-j, --json', 'Output results as JSON', false)
  .option('-o, --output <file>', 'Write results to file')
  .option('--include-content', 'Include raw content in the report (may be large)', false)
  .option('--include-grouped', 'Include grouped vulnerabilities in the report', false)
  .action(async (file, options) => {
    const spinner = ora('Scanning PDF for XSS vulnerabilities...').start();
    
    try {
      // Scan the PDF
      const scanOptions = {
        threshold: options.threshold,
        includeRawContent: options.includeContent,
        includeFullDetails: options.verbose,
        includeGrouped: options.includeGrouped
      };
      
      const results = await scanPdf(file, scanOptions);
      
      // Handle scan results
      if (!results.success) {
        spinner.fail(`Error scanning PDF: ${results.error}`);
        process.exit(1);
      }
      
      // Display results
      if (results.vulnerabilities.length > 0) {
        spinner.warn(`Found ${results.vulnerabilities.length} potential XSS vulnerabilities!`);
      } else {
        spinner.succeed('No XSS vulnerabilities detected.');
      }
      
      // Output results
      if (options.json) {
        if (options.output) {
          fs.writeFileSync(options.output, JSON.stringify(results, null, 2));
          console.log(`\nResults written to ${options.output}`);
        } else {
          console.log(JSON.stringify(results, null, 2));
        }
      } else {
        outputFormattedResults(results, options);
        
        if (options.output) {
          fs.writeFileSync(options.output, JSON.stringify(results, null, 2));
          console.log(`\nDetailed results written to ${options.output}`);
        }
      }
    } catch (error) {
      spinner.fail(`Error: ${error.message}`);
      process.exit(1);
    }
  });

/**
 * Output formatted results to the console
 * @param {Object} results - Scan results
 * @param {Object} options - CLI options
 */
function outputFormattedResults(results, options) {
  console.log('\n' + chalk.bold('PDF XSS Vulnerability Report'));
  console.log('═══════════════════════════════\n');
  
  console.log(chalk.bold('File:'), path.basename(results.summary.fileName));
  console.log(chalk.bold('Pages:'), results.metadata.pageCount);
  console.log(chalk.bold('Safe to use:'), results.summary.safeToUse 
    ? chalk.green('Yes') 
    : chalk.red('No - XSS vulnerabilities detected'));
  console.log(chalk.bold('Risk level:'), formatRiskLevel(results.summary.riskLevel));
  console.log(chalk.bold('Scanned:'), new Date(results.summary.timestamp).toLocaleString());
  
  // Show vulnerability counts
  if (results.summary.vulnerabilityCount > 0) {
    console.log('\n' + chalk.bold('Vulnerabilities Found:'), results.summary.vulnerabilityCount);
    
    // By severity
    console.log('\n' + chalk.bold('By Severity:'));
    const severityCounts = results.summary.severityCounts;
    Object.keys(severityCounts).forEach(severity => {
      const count = severityCounts[severity];
      const color = getSeverityColor(severity);
      console.log(`  ${color(severity.toUpperCase())}: ${count}`);
    });
    
    // By type
    console.log('\n' + chalk.bold('By Type:'));
    const typeCounts = results.summary.typeCounts;
    Object.keys(typeCounts).forEach(type => {
      console.log(`  ${formatType(type)}: ${typeCounts[type]}`);
    });
    
    // List vulnerabilities
    if (options.verbose) {
      console.log('\n' + chalk.bold('Vulnerability Details:'));
      results.vulnerabilities.forEach((vuln, index) => {
        console.log(`\n${index + 1}. ${chalk.bold(vuln.name)}`);
        console.log(`   Type: ${formatType(vuln.type)}`);
        console.log(`   Severity: ${getSeverityColor(vuln.severity)(vuln.severity.toUpperCase())}`);
        console.log(`   Description: ${vuln.description}`);
        if (vuln.matchedText) {
          console.log(`   Matched: ${chalk.grey(vuln.matchedText)}`);
        }
        if (vuln.location) {
          console.log(`   Location: Line ${vuln.location.line}, Column ${vuln.location.column}`);
        }
        if (vuln.context) {
          console.log(`   Context: ${chalk.grey('...')}${chalk.yellow(vuln.context)}${chalk.grey('...')}`);
        }
      });
    }
  }
  
  console.log('\n' + chalk.bold('Recommendation:'));
  if (results.summary.safeToUse) {
    console.log(chalk.green('✓ This PDF appears safe from XSS vulnerabilities.'));
  } else {
    console.log(chalk.red('✗ This PDF contains potential XSS vulnerabilities.'));
    console.log(chalk.red('  Review and sanitize the document before use.'));
  }
  
  console.log(''); // Add final newline
}

/**
 * Format risk level with appropriate color
 * @param {string} level - Risk level
 * @returns {string} Colored risk level
 */
function formatRiskLevel(level) {
  switch (level) {
    case 'none': return chalk.green('None');
    case 'low': return chalk.blue('Low');
    case 'medium': return chalk.yellow('Medium');
    case 'high': return chalk.red('High');
    case 'critical': return chalk.bgRed.white('Critical');
    default: return level;
  }
}

/**
 * Get chalk color function for severity
 * @param {string} severity - Severity level
 * @returns {Function} Chalk color function
 */
function getSeverityColor(severity) {
  switch (severity) {
    case 'low': return chalk.blue;
    case 'medium': return chalk.yellow;
    case 'high': return chalk.red;
    case 'critical': return chalk.bgRed.white;
    default: return chalk.white;
  }
}

/**
 * Format vulnerability type for display
 * @param {string} type - Vulnerability type
 * @returns {string} Formatted type
 */
function formatType(type) {
  switch (type) {
    case 'xss': return 'XSS Pattern';
    case 'js-injection': return 'JavaScript Injection';
    case 'form-injection': return 'Form Injection';
    default: return type.charAt(0).toUpperCase() + type.slice(1);
  }
}

// Parse command-line arguments
program.parse();