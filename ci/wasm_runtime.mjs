import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';

const [binaryPath, reportPath] = process.argv.slice(2);
const binary = fs.readFileSync(binaryPath);
const report = {
  binary: binaryPath,
  sha256: crypto.createHash('sha256').update(binary).digest('hex'),
  node: process.versions,
  cases: {},
  status: 'running',
};
try {
  const { instance } = await WebAssembly.instantiate(binary);
  report.pointer_width = instance.exports.pointer_width();
  assert.equal(report.pointer_width, 32);
  for (const name of ['codec_cases', 'error_cases', 'formatting_cases', 'owned_cases']) {
    report.phase = name;
    console.error(`Executing ${name}`);
    const count = instance.exports[name]();
    assert(Number.isSafeInteger(count) && count > 0, `${name} must execute cases`);
    report.cases[name] = count;
  }
  report.status = 'passed';
  delete report.phase;
  console.log(JSON.stringify(report.cases));
} catch (error) {
  report.status = 'failed';
  report.error = String(error.stack ?? error);
  console.error(report.error);
  process.exitCode = 1;
} finally {
  fs.writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`);
}
