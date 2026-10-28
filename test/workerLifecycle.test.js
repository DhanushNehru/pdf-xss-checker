const { spawnSync } = require('child_process');
const path = require('path');

// Subprocesses do not inherit Jest's synchronous-scanner test shortcut.
function run(code) {
  const env = { ...process.env };
  delete env.NODE_ENV;
  delete env.JEST_WORKER_ID;
  const result = spawnSync(process.execPath, ['-e', code], {
    cwd: path.join(__dirname, '..'), env, timeout: 5000, encoding: 'utf8'
  });
  expect(result.error).toBeUndefined();
  expect(result.status).toBe(0);
  return result.stdout;
}

const setup = `const p = require('./src/workerPool');
const fixture = Buffer.from('%PDF-1.4\\nbenign lifecycle fixture');`;

test('importing an idle pool does not hold the process open', () => {
  expect(run(`${setup} console.log('idle');`)).toContain('idle');
});

test('queued tasks all finish before natural process exit', () => {
  expect(run(`${setup}
    Promise.all(Array.from({length: 12}, () => p.runTask(fixture, {detectors:[]})))
      .then(results => {
        if (!results.every(r => r.success)) throw new Error('scan failed');
        console.log('completed:' + results.length);
      });`)).toContain('completed:12');
});

test('a handled worker task error allows reuse and natural exit', () => {
  expect(run(`${setup}
    p.runTask(fixture, {detectors:42}).catch(async () => {
      const result = await p.runTask(fixture, {detectors:[]});
      if (!result.success) throw new Error('reuse failed');
      console.log('recovered');
    });`)).toContain('recovered');
});

test('a postMessage cloning error releases its worker and callback', () => {
  expect(run(`${setup}
    p.runTask(fixture, {nonCloneable:()=>{}}).catch(async error => {
      if (error.name !== 'DataCloneError') throw error;
      const result = await p.runTask(fixture, {detectors:[]});
      if (!result.success || p.callbacks.size !== 0) throw new Error('cleanup failed');
      console.log('clone-error-recovered');
    });`)).toContain('clone-error-recovered');
});
