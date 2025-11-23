// Windows Service wrapper for TriTerm
const path = require('path');

// This template is used by the service installer
module.exports = {
  name: 'TriTerm Server',
  description: 'TriTerm Multi-Terminal Server Service',
  script: '{{INSTALL_DIR}}\\server\\index.js',
  env: [
    {
      name: 'NODE_ENV',
      value: 'production',
    },
    {
      name: 'PORT',
      value: '{{PORT}}',
    },
    {
      name: 'DATABASE_URL',
      value: '{{DATABASE_URL}}',
    },
  ],
  workingDirectory: '{{INSTALL_DIR}}',
  logDirectory: '{{LOG_DIR}}',
  nodeOptions: ['--max-old-space-size=4096'],
  allowServiceLogon: true,
};
