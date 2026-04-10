const express = require('express');
const dns = require('dns').promises;
const validator = require('validator');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// API Key Authentication Middleware
app.use((req, res, next) => {
  if (req.path === '/health') return next();
  const key = req.headers['x-api-key'];
  if (process.env.API_KEY && (!key || key !== process.env.API_KEY)) {
    return res.status(401).json({ success: false, error: 'Invalid or missing API key' });
  }
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ success: true, data: { status: 'healthy' } });
});

// DNS Health Check Endpoint
app.post('/check', async (req, res) => {
  try {
    const { domain } = req.body;
    
    // Validate input
    if (!domain) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing domain parameter',
        message: 'Domain name is required'
      });
    }
    
    if (!validator.isFQDN(domain)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid domain format',
        message: 'Please provide a valid fully qualified domain name'
      });
    }
    
    const results = {
      domain: domain,
      timestamp: new Date().toISOString(),
      checks: {
        domainResolves: false,
        mxRecords: [],
        hasMX: false,
        spfRecord: null,
        hasSPF: false,
        dkimSelectors: [],
        hasDKIM: false
      }
    };
    
    // Check if domain resolves to an IP
    try {
      const addresses = await dns.resolve4(domain);
      results.checks.domainResolves = addresses.length > 0;
    } catch (err) {
      results.checks.domainResolves = false;
    }
    
    // Check MX records
    try {
      const mxRecords = await dns.resolveMx(domain);
      results.checks.mxRecords = mxRecords.map(record => ({
        priority: record.priority,
        exchange: record.exchange
      }));
      results.checks.hasMX = mxRecords.length > 0;
    } catch (err) {
      results.checks.mxRecords = [];
      results.checks.hasMX = false;
    }
    
    // Check SPF record
    try {
      const txtRecords = await dns.resolveTxt(domain);
      const spfRecord = txtRecords.find(txt => txt.join('').startsWith('v=spf1'));
      if (spfRecord) {
        results.checks.spfRecord = spfRecord.join('');
        results.checks.hasSPF = true;
      }
    } catch (err) {
      results.checks.spfRecord = null;
      results.checks.hasSPF = false;
    }
    
    // Check for common DKIM selectors
    const commonSelectors = ['default', 'google', 'k1', 'selector1', 'selector2'];
    const dkimChecks = [];
    
    for (const selector of commonSelectors) {
      try {
        const dkimDomain = `${selector}._domainkey.${domain}`;
        const txtRecords = await dns.resolveTxt(dkimDomain);
        if (txtRecords.length > 0) {
          dkimChecks.push(selector);
        }
      } catch (err) {
        // Continue checking other selectors
      }
    }
    
    results.checks.dkimSelectors = dkimChecks;
    results.checks.hasDKIM = dkimChecks.length > 0;
    
    // Overall health score
    const healthScore = [
      results.checks.domainResolves,
      results.checks.hasMX,
      results.checks.hasSPF,
      results.checks.hasDKIM
    ].filter(Boolean).length;
    
    results.overallHealth = {
      score: healthScore,
      status: healthScore >= 3 ? 'healthy' : healthScore >= 2 ? 'warning' : 'critical',
      recommendations: []
    };
    
    // Add recommendations based on checks
    if (!results.checks.domainResolves) {
      results.overallHealth.recommendations.push('Domain does not resolve - check DNS configuration');
    }
    if (!results.checks.hasMX) {
      results.overallHealth.recommendations.push('No MX records found - email delivery will fail');
    }
    if (!results.checks.hasSPF) {
      results.overallHealth.recommendations.push('No SPF record found - consider adding one for email authentication');
    }
    if (!results.checks.hasDKIM) {
      results.overallHealth.recommendations.push('No DKIM records found - consider setting up DKIM for email authentication');
    }
    
    res.json({ success: true, data: results });
    
  } catch (error) {
    console.error('DNS check error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'Internal server error',
      message: 'An error occurred while checking DNS records'
    });
  }
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json({ 
    success: false, 
    error: 'Not found',
    message: 'The requested endpoint does not exist'
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    success: false, 
    error: 'Internal server error',
    message: 'An unexpected error occurred'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`DNS Health Checker API running on port ${PORT}`);
});