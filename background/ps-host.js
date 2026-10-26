/**
 * MY LAPTOP GUARD - Persistent PowerShell Host (ps-host.js)
 * High-performance, persistent PowerShell child process daemon.
 * Eliminates per-check process spawning overhead, drastically cutting CPU spikes and latency.
 * Implements strict command queuing, boundary markers, per-command timeouts,
 * crash auto-restart with backoff, and output size bounds.
 */

const { spawn } = require('child_process');
const crypto = require('crypto');

class PersistentPowerShellHost {
  constructor(options = {}) {
    this.maxBufferSize = options.maxBufferSize || 5 * 1024 * 1024; // 5MB limit
    this.defaultTimeoutMs = options.defaultTimeoutMs || 8000;
    this.child = null;
    this.pid = null;
    this.queue = [];
    this.currentTask = null;
    this.stdoutBuffer = '';
    this.stderrBuffer = '';
    this.crashCount = 0;
    this.lastRestartTime = 0;
    this.isStopping = false;
    this.commandsExecuted = 0;
    this.lastDurationMs = 0;
  }

  /**
   * Initializes or restarts the persistent PowerShell child process
   */
  start() {
    if (process.platform !== 'win32') return;
    if (this.child && !this.child.killed) return;
    this.isStopping = false;

    try {
      this.child = spawn('powershell.exe', [
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-Command', '-'
      ], {
        windowsHide: true,
        stdio: ['pipe', 'pipe', 'pipe']
      });

      this.pid = this.child.pid;
      this.stdoutBuffer = '';
      this.stderrBuffer = '';

      this.child.stdout.on('data', (chunk) => this._onStdout(chunk));
      this.child.stderr.on('data', (chunk) => this._onStderr(chunk));

      this.child.on('error', (err) => {
        this._handleCrash(`Process error: ${err.message}`);
      });

      this.child.on('exit', (code, signal) => {
        if (!this.isStopping) {
          this._handleCrash(`Process exited unexpectedly with code ${code}, signal ${signal}`);
        }
      });
    } catch (err) {
      this._handleCrash(`Failed to spawn powershell.exe: ${err.message}`);
    }
  }

  _handleCrash(reason) {
    this.child = null;
    this.pid = null;
    this.crashCount++;

    if (this.currentTask) {
      clearTimeout(this.currentTask.timer);
      this.currentTask.reject(new Error(`PowerShell host crashed: ${reason}`));
      this.currentTask = null;
    }

    if (this.isStopping) return;

    // Exponential backoff up to 10 seconds
    const now = Date.now();
    const delay = Math.min(1000 * Math.pow(1.5, Math.min(this.crashCount, 6)), 10000);
    this.lastRestartTime = now;

    setTimeout(() => {
      if (!this.isStopping) {
        this.start();
        this._processQueue();
      }
    }, delay);
  }

  _onStdout(chunk) {
    this.stdoutBuffer += chunk.toString();
    if (this.stdoutBuffer.length > this.maxBufferSize) {
      if (this.currentTask) {
        clearTimeout(this.currentTask.timer);
        this.currentTask.reject(new Error('PowerShell output exceeded maximum buffer size limit (5MB)'));
        this.currentTask = null;
        this._restart();
        return;
      }
    }

    if (!this.currentTask) return;

    const endMarker = `__PS_HOST_END_${this.currentTask.id}__`;
    const endIdx = this.stdoutBuffer.indexOf(endMarker);

    if (endIdx !== -1) {
      clearTimeout(this.currentTask.timer);
      const startMarker = `__PS_HOST_START_${this.currentTask.id}__`;
      const startIdx = this.stdoutBuffer.indexOf(startMarker);

      let payload = '';
      if (startIdx !== -1 && endIdx > startIdx) {
        payload = this.stdoutBuffer.substring(startIdx + startMarker.length, endIdx).trim();
      } else {
        payload = this.stdoutBuffer.substring(0, endIdx).trim();
      }

      // Slice out the processed part from buffer
      this.stdoutBuffer = this.stdoutBuffer.substring(endIdx + endMarker.length);

      const task = this.currentTask;
      this.currentTask = null;
      this.commandsExecuted++;
      this.lastDurationMs = Date.now() - task.startTime;

      // Check for error marker
      const errMarker = `__PS_HOST_ERR_${task.id}__`;
      if (payload.includes(errMarker)) {
        const parts = payload.split(errMarker);
        task.reject(new Error(parts[1] ? parts[1].trim() : 'PowerShell script execution error'));
      } else {
        if (task.asJson) {
          try {
            if (!payload || payload === 'null' || payload === '$null') {
              task.resolve(null);
            } else {
              task.resolve(JSON.parse(payload));
            }
          } catch (jsonErr) {
            // If output was not valid JSON, reject or return string
            task.reject(new Error(`Failed to parse JSON from PowerShell: ${jsonErr.message}. Output was: ${payload.substring(0, 200)}`));
          }
        } else {
          task.resolve(payload);
        }
      }

      this._processQueue();
    }
  }

  _onStderr(chunk) {
    this.stderrBuffer += chunk.toString();
    if (this.stderrBuffer.length > 500000) {
      this.stderrBuffer = this.stderrBuffer.substring(this.stderrBuffer.length - 200000);
    }
  }

  _restart() {
    if (this.child) {
      try { this.child.kill(); } catch (e) {}
    }
    this.start();
    this._processQueue();
  }

  _processQueue() {
    if (this.currentTask || this.queue.length === 0) return;
    if (!this.child || this.child.killed) {
      this.start();
      if (!this.child) return;
    }

    const task = this.queue.shift();
    this.currentTask = task;
    task.startTime = Date.now();

    task.timer = setTimeout(() => {
      task.reject(new Error(`PowerShell command timed out after ${task.timeoutMs}ms`));
      this.currentTask = null;
      this._restart();
    }, task.timeoutMs);

    const scriptBlock = `
Write-Output "__PS_HOST_START_${task.id}__"
try {
  $res = & {
${task.script}
  }
  if ($null -ne $res) {
    ${task.asJson ? '$res | ConvertTo-Json -Compress -Depth 4' : '$res'}
  }
} catch {
  Write-Output "__PS_HOST_ERR_${task.id}__"
  $_.Exception.Message
}
Write-Output "__PS_HOST_END_${task.id}__"
`;

    try {
      this.child.stdin.write(scriptBlock + '\r\n');
    } catch (writeErr) {
      clearTimeout(task.timer);
      task.reject(new Error(`Failed to write to PowerShell stdin: ${writeErr.message}`));
      this.currentTask = null;
      this._restart();
    }
  }

  /**
   * Enqueues a PowerShell script to run on the persistent host.
   * Returns a Promise resolving to parsed JSON or string output.
   */
  execute(script, options = {}) {
    if (process.platform !== 'win32') {
      return Promise.resolve(options.asJson !== false ? {} : '');
    }

    if (!script || typeof script !== 'string') {
      return Promise.reject(new Error('Invalid PowerShell script provided'));
    }

    const timeoutMs = options.timeoutMs || this.defaultTimeoutMs;
    const asJson = options.asJson !== false; // Default true
    const id = crypto.randomBytes(6).toString('hex');

    return new Promise((resolve, reject) => {
      this.queue.push({
        id,
        script: script.trim(),
        timeoutMs,
        asJson,
        resolve,
        reject
      });

      this._processQueue();
    });
  }

  getStatus() {
    return {
      running: !!(this.child && !this.child.killed),
      pid: this.pid,
      queueLength: this.queue.length,
      commandsExecuted: this.commandsExecuted,
      lastDurationMs: this.lastDurationMs,
      crashes: this.crashCount
    };
  }

  shutdown() {
    this.isStopping = true;
    if (this.child) {
      try {
        this.child.stdin.write('exit\r\n');
        setTimeout(() => {
          if (this.child) {
            try { this.child.kill(); } catch (e) {}
          }
        }, 1000);
      } catch (e) {
        try { this.child.kill(); } catch (k) {}
      }
    }
  }
}

// Singleton instance
const psHost = new PersistentPowerShellHost();
module.exports = psHost;
module.exports.PersistentPowerShellHost = PersistentPowerShellHost;
