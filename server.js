'use strict';

const express = require('express');
const { evaluateActionFirewall } = require('./logic');

const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'action-firewall' });
});

app.get('/healthz', (req, res) => {
  res.json({ status: 'ok' });
});

app.post('/action-firewall', (req, res) => {
  try {
    const result = evaluateActionFirewall(req.body || {});
    res.status(200).json(result);
  } catch (err) {
    res.status(200).json({ decision: 'block', reason: 'INVALID_SCHEMA' });
  }
});

const PORT = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`action-firewall listening on port ${PORT}`);
  });
}

module.exports = app;
