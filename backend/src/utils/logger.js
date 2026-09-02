import fs from 'fs';
import path from 'path';

const logsDir = './logs';
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

const formatLog = (level, data) => {
  const timestamp = new Date().toISOString();
  return JSON.stringify({
    level,
    timestamp,
    ...data,
  });
};

export const logger = {
  info: (data) => {
    const log = formatLog('INFO', data);
    console.log(log);
    if (process.env.NODE_ENV === 'production') {
      fs.appendFileSync(path.join(logsDir, 'app.log'), log + '\n');
    }
  },
  warn: (data) => {
    const log = formatLog('WARN', data);
    console.warn(log);
    fs.appendFileSync(path.join(logsDir, 'warn.log'), log + '\n');
  },
  error: (data) => {
    const log = formatLog('ERROR', data);
    console.error(log);
    fs.appendFileSync(path.join(logsDir, 'error.log'), log + '\n');
  },
};
