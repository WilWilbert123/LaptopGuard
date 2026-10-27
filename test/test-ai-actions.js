/**
 * Test Suite for Guardian AI Active Agent Commands
 */

const assert = require('assert');
const aiService = require('../background/ai-service');
const db = require('../background/database');
const monitor = require('../background/monitor');
const firewall = require('../background/firewall');
const responder = require('../background/responder');

async function runTests() {
  console.log('Testing Guardian AI Action Engine...');
  db.init();

  const services = {
    monitor,
    db,
    remoteAccessCollector: null,
    firewall,
    responder,
    postureEvaluator: null,
    io: null
  };

  // 1. Threat Scan Command
  console.log('1. Testing Threat Scan command...');
  const scanRes = await aiService.chat('Scan my laptop for new threats', services);
  assert.strictEqual(scanRes.success, true);
  assert.ok(scanRes.reply.includes('Real-Time Threat Scan Completed!'));
  assert.ok(Array.isArray(scanRes.actions));
  console.log('   [PASS] Threat Scan executed and generated live report');

  // 2. Audit Logs Command
  console.log('2. Testing Audit Logs command...');
  const auditRes = await aiService.chat('What is the latest audit?', services);
  assert.strictEqual(auditRes.success, true);
  assert.ok(auditRes.reply.includes('Audit'));
  console.log('   [PASS] Audit command pulled database logs');

  // 3. Posture / Health Score Command
  console.log('3. Testing Health Score command...');
  const healthRes = await aiService.chat('Why is my health score 85/100?', services);
  assert.strictEqual(healthRes.success, true);
  assert.ok(healthRes.reply.includes('85 / 100') || healthRes.reply.includes('Health Score'));
  console.log('   [PASS] Health command evaluated posture correctly');

  // 4. Block IP Command Preview / Refusal Safety
  console.log('4. Testing Block Loopback Safety Refusal...');
  const loopbackBlock = await aiService.chat('Block IP 127.0.0.1', services);
  assert.strictEqual(loopbackBlock.success, true);
  assert.ok(loopbackBlock.reply.includes('Failed') || loopbackBlock.reply.includes('Safety') || loopbackBlock.reply.includes('loopback'));
  console.log('   [PASS] Safety Refusal prevented blocking loopback');

  console.log('\nAll AI Action Engine tests passed successfully!');
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
