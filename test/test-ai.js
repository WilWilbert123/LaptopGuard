const http = require('http');

async function testQuery(message) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ message });
    const req = http.request({
      hostname: '127.0.0.1',
      port: 3000,
      path: '/api/ai/chat',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData)
      }
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          resolve({ raw: body });
        }
      });
    });

    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

async function run() {
  console.log('--- Testing Query 1: What is an active connection? ---');
  const r1 = await testQuery('What is an active connection?');
  console.log('Source:', r1.source);
  console.log('Follow-ups count:', r1.followUps ? r1.followUps.length : 0);
  console.log('Follow-ups:', r1.followUps);
  console.log('Answer preview:', r1.answer ? r1.answer.substring(0, 200) + '...' : r1);

  console.log('\n--- Testing Query 2: Is my laptop safe right now? ---');
  const r2 = await testQuery('Is my laptop safe right now?');
  console.log('Source:', r2.source);
  console.log('Follow-ups count:', r2.followUps ? r2.followUps.length : 0);
  console.log('Follow-ups:', r2.followUps);
  console.log('Answer preview:', r2.answer ? r2.answer.substring(0, 200) + '...' : r2);

  console.log('\n--- Testing Query 3: What is a listening port? ---');
  const r3 = await testQuery('What is a listening port?');
  console.log('Source:', r3.source);
  console.log('Follow-ups count:', r3.followUps ? r3.followUps.length : 0);
  console.log('Follow-ups:', r3.followUps);
  console.log('Answer preview:', r3.answer ? r3.answer.substring(0, 200) + '...' : r3);
}

run().catch(console.error);
