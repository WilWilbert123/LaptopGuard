/**
 * MY LAPTOP GUARD - Local Static Malware Analysis & Reverse Engineering (analyzer.js)
 *
 * STRICT LOCAL-ONLY BOUNDARY:
 * - Performs static analysis ONLY on local files already present on this laptop.
 * - NEVER connects to, probes, or sends data to any remote IP, URL, or machine.
 * - NEVER executes the sample. Dynamic analysis must be performed manually by the owner
 *   inside an isolated sandbox or VM.
 * - Extracts hashes, PE headers, section entropy, strings, and passive IOCs.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { redactSensitiveData } = require('./redact');
const psHost = require('./ps-host');
const db = require('./database');

// Sane caps
const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100 MB max for static inspection
const MAX_STRINGS_EXTRACT = 3000;
const MIN_STRING_LEN = 4;

// Common PE Packer signatures / section names
const PACKER_SECTIONS = new Set([
  '.upx0', '.upx1', '.upx2', 'upx0', 'upx1', 'upx',
  '.vmp0', '.vmp1', '.vmp2', 'vmp',
  '.themida', '.aspack', '.nsp0', '.nsp1',
  '.mpress1', '.mpress2', '.enigma1', '.enigma2',
  'pec1', 'pec2', '.petite'
]);

// System directories requiring extra warning/confirmation
const RESTRICTED_SYSTEM_DIRS = [
  'c:\\windows\\system32',
  'c:\\windows\\syswow64',
  'c:\\windows\\winsxs',
  'c:\\windows\\boot'
];

/**
 * Calculates Shannon Entropy of a buffer: H = -sum(p * log2(p))
 * Returns value between 0.0 (uniform) and 8.0 (completely random / compressed / encrypted).
 */
function calculateShannonEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;

  const frequencies = new Uint32Array(256);
  for (let i = 0; i < buffer.length; i++) {
    frequencies[buffer[i]]++;
  }

  let entropy = 0;
  const total = buffer.length;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / total;
      entropy -= p * Math.log2(p);
    }
  }

  return Math.round(entropy * 1000) / 1000;
}

/**
 * Detects file format / magic bytes
 */
function detectFileType(buffer) {
  if (!buffer || buffer.length < 4) return { type: 'Unknown', mime: 'application/octet-stream' };

  if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
    return { type: 'PE/COFF Executable (Windows DOS/PE)', mime: 'application/x-dosexec', isPe: true };
  }
  if (buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
    return { type: 'ELF Binary (Linux/Unix)', mime: 'application/x-executable', isPe: false };
  }
  if (buffer[0] === 0x50 && buffer[1] === 0x4B && buffer[2] === 0x03 && buffer[3] === 0x04) {
    return { type: 'ZIP Archive / Office OpenXML', mime: 'application/zip', isPe: false };
  }
  if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
    return { type: 'PDF Document', mime: 'application/pdf', isPe: false };
  }
  if (buffer[0] === 0xD0 && buffer[1] === 0xCF && buffer[2] === 0x11 && buffer[3] === 0xE0) {
    return { type: 'Compound OLE2 Document (MS Office legacy)', mime: 'application/x-ole-storage', isPe: false };
  }
  if (buffer[0] === 0x4C && buffer[1] === 0x00 && buffer[2] === 0x00 && buffer[3] === 0x00) {
    return { type: 'Windows Shell Link (.lnk)', mime: 'application/x-ms-shortcut', isPe: false };
  }

  // Check if plain text script (PowerShell, Batch, VBS)
  const sample = buffer.slice(0, 512).toString('ascii');
  if (/^#!(.*)|param\s*\(|function\s+|echo\s+off|setlocal|dim\s+/i.test(sample)) {
    return { type: 'Script Text (PowerShell / Batch / VBS)', mime: 'text/plain', isPe: false };
  }

  return { type: 'Binary Data', mime: 'application/octet-stream', isPe: false };
}

/**
 * Pure JavaScript Portable Executable (PE) Header Parser
 */
function parsePeHeader(buffer) {
  try {
    if (buffer.length < 64) return null;
    if (buffer[0] !== 0x4D || buffer[1] !== 0x5A) return null; // 'MZ'

    const e_lfanew = buffer.readUInt32LE(0x3C);
    if (e_lfanew + 24 > buffer.length) return null;

    // Check PE signature: 'PE\0\0' (0x00004550)
    const peSig = buffer.readUInt32LE(e_lfanew);
    if (peSig !== 0x00004550) return null;

    const coffOffset = e_lfanew + 4;
    const machine = buffer.readUInt16LE(coffOffset);
    const numberOfSections = buffer.readUInt16LE(coffOffset + 2);
    const timeDateStamp = buffer.readUInt32LE(coffOffset + 4);
    const sizeOfOptionalHeader = buffer.readUInt16LE(coffOffset + 16);
    const characteristics = buffer.readUInt16LE(coffOffset + 18);

    let machineName = 'Unknown';
    if (machine === 0x014C) machineName = 'x86 (32-bit Intel/AMD)';
    else if (machine === 0x8664) machineName = 'x64 (64-bit AMD64)';
    else if (machine === 0xAA64) machineName = 'ARM64';
    else if (machine === 0x01C0) machineName = 'ARM';

    const compileTime = new Date(timeDateStamp * 1000).toISOString();

    // Optional Header
    let subsystem = 'Unknown';
    let entryPointRva = 0;
    let imageBase = '0';
    let is64Bit = false;

    if (sizeOfOptionalHeader > 0 && coffOffset + 20 + sizeOfOptionalHeader <= buffer.length) {
      const optOffset = coffOffset + 20;
      const optMagic = buffer.readUInt16LE(optOffset);
      is64Bit = (optMagic === 0x020B); // PE32+
      entryPointRva = buffer.readUInt32LE(optOffset + 16);

      if (is64Bit) {
        imageBase = '0x' + buffer.readBigUInt64LE(optOffset + 24).toString(16);
      } else {
        imageBase = '0x' + buffer.readUInt32LE(optOffset + 28).toString(16);
      }

      const subId = buffer.readUInt16LE(optOffset + (is64Bit ? 68 : 68));
      if (subId === 1) subsystem = 'Native / Device Driver';
      else if (subId === 2) subsystem = 'Windows GUI';
      else if (subId === 3) subsystem = 'Windows CUI / Console';
    }

    // Section Table
    const sectionTableOffset = coffOffset + 20 + sizeOfOptionalHeader;
    const sections = [];
    let highEntropyCount = 0;
    let packerSectionDetected = null;

    for (let i = 0; i < numberOfSections && (sectionTableOffset + (i + 1) * 40 <= buffer.length); i++) {
      const sOffset = sectionTableOffset + i * 40;
      let name = buffer.toString('ascii', sOffset, sOffset + 8).replace(/\0/g, '').trim();
      const virtualSize = buffer.readUInt32LE(sOffset + 8);
      const virtualAddress = buffer.readUInt32LE(sOffset + 12);
      const sizeOfRawData = buffer.readUInt32LE(sOffset + 16);
      const pointerToRawData = buffer.readUInt32LE(sOffset + 20);
      const sectionChars = buffer.readUInt32LE(sOffset + 36);

      // Extract section raw bytes to calculate entropy
      let entropy = 0;
      if (pointerToRawData > 0 && sizeOfRawData > 0 && pointerToRawData + sizeOfRawData <= buffer.length) {
        const secBytes = buffer.slice(pointerToRawData, pointerToRawData + sizeOfRawData);
        entropy = calculateShannonEntropy(secBytes);
      }

      if (entropy > 7.0) highEntropyCount++;
      if (PACKER_SECTIONS.has(name.toLowerCase())) packerSectionDetected = name;

      sections.push({
        index: i,
        name,
        virtualAddress: '0x' + virtualAddress.toString(16),
        virtualSize,
        rawSize: sizeOfRawData,
        rawPointer: pointerToRawData,
        characteristics: '0x' + sectionChars.toString(16),
        entropy,
        isHighEntropy: entropy > 7.0
      });
    }

    return {
      isPe: true,
      machine: machineName,
      is64Bit,
      compileTimestampUtc: compileTime,
      entryPointRva: '0x' + entryPointRva.toString(16),
      imageBase,
      subsystem,
      characteristics: '0x' + characteristics.toString(16),
      numberOfSections,
      sections,
      packingIndicators: {
        isPacked: highEntropyCount > 0 || !!packerSectionDetected,
        highEntropySectionsCount: highEntropyCount,
        packerSectionDetected
      }
    };
  } catch (err) {
    return { parseError: err.message };
  }
}

/**
 * Extracts printable ASCII and UTF-16 strings with sane length limits & secret redaction
 */
function extractStrings(buffer) {
  const strings = [];
  let currentAscii = '';

  // 1. ASCII extraction
  for (let i = 0; i < buffer.length; i++) {
    const b = buffer[i];
    if (b >= 0x20 && b <= 0x7E) {
      currentAscii += String.fromCharCode(b);
    } else {
      if (currentAscii.length >= MIN_STRING_LEN) {
        strings.push(currentAscii);
        if (strings.length >= MAX_STRINGS_EXTRACT) break;
      }
      currentAscii = '';
    }
  }

  // 2. UTF-16LE extraction (if budget remains)
  if (strings.length < MAX_STRINGS_EXTRACT) {
    let currentWide = '';
    for (let i = 0; i < buffer.length - 1; i += 2) {
      const b1 = buffer[i];
      const b2 = buffer[i + 1];
      if (b2 === 0x00 && b1 >= 0x20 && b1 <= 0x7E) {
        currentWide += String.fromCharCode(b1);
      } else {
        if (currentWide.length >= MIN_STRING_LEN) {
          strings.push(currentWide);
          if (strings.length >= MAX_STRINGS_EXTRACT) break;
        }
        currentWide = '';
      }
    }
  }

  // Redact any discovered API keys or passwords in the extracted strings
  return strings.map(s => redactSensitiveData(s));
}

/**
 * Passive IOC extraction (Zero network requests)
 */
function extractIocs(strings = []) {
  const iocs = {
    ipv4: new Set(),
    domains: new Set(),
    urls: new Set(),
    emails: new Set(),
    registryKeys: new Set(),
    filePaths: new Set(),
    hashes: new Set(),
    mutexes: new Set()
  };

  const IP_REGEX = /\b(?!127\.|0\.|255\.)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;
  const DOMAIN_REGEX = /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|net|org|io|ru|xyz|top|cc|biz|info|onion|me|app|dev|pro))\b/i;
  const URL_REGEX = /https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=]+/i;
  const EMAIL_REGEX = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
  const REG_REGEX = /\b(HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[A-Za-z0-9_\-\\]+/i;
  const PATH_REGEX = /\b([C-Z]:\\[A-Za-z0-9_. \-\\]+)/i;
  const HASH_REGEX = /\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b/;
  const MUTEX_REGEX = /\b(Global\\|Local\\)[A-Za-z0-9_\-]{4,}\b/i;

  for (const s of strings) {
    if (s.length > 256) continue;

    const urlMatch = s.match(URL_REGEX);
    if (urlMatch) iocs.urls.add(urlMatch[0]);

    const ipMatch = s.match(IP_REGEX);
    if (ipMatch) iocs.ipv4.add(ipMatch[1]);

    const domMatch = s.match(DOMAIN_REGEX);
    if (domMatch && !s.includes('@')) iocs.domains.add(domMatch[1].toLowerCase());

    const emailMatch = s.match(EMAIL_REGEX);
    if (emailMatch) iocs.emails.add(emailMatch[0].toLowerCase());

    const regMatch = s.match(REG_REGEX);
    if (regMatch) iocs.registryKeys.add(regMatch[0]);

    const pathMatch = s.match(PATH_REGEX);
    if (pathMatch) iocs.filePaths.add(pathMatch[1]);

    const hashMatch = s.match(HASH_REGEX);
    if (hashMatch) iocs.hashes.add(hashMatch[1].toLowerCase());

    const mutMatch = s.match(MUTEX_REGEX);
    if (mutMatch) iocs.mutexes.add(mutMatch[0]);
  }

  return {
    ipv4: Array.from(iocs.ipv4).slice(0, 50),
    domains: Array.from(iocs.domains).slice(0, 50),
    urls: Array.from(iocs.urls).slice(0, 50),
    emails: Array.from(iocs.emails).slice(0, 50),
    registryKeys: Array.from(iocs.registryKeys).slice(0, 50),
    filePaths: Array.from(iocs.filePaths).slice(0, 50),
    hashes: Array.from(iocs.hashes).slice(0, 50),
    mutexes: Array.from(iocs.mutexes).slice(0, 50),
    disclaimer: 'Extracted from static file contents only. Passive and unverified against any network.'
  };
}

/**
 * Maps strings and symbols to behavioral capability hints
 */
function inferCapabilities(arg1 = [], arg2 = null) {
  let strings = [];
  let peInfo = null;

  if (Array.isArray(arg1)) {
    strings = arg1;
    peInfo = arg2;
  } else if (Array.isArray(arg2)) {
    strings = arg2;
    peInfo = arg1;
  } else if (arg1 && typeof arg1 === 'object') {
    peInfo = arg1;
    strings = Array.isArray(arg2) ? arg2 : [];
  }

  const caps = [];
  const joined = (strings || []).join(' ').toLowerCase();

  function check(id, title, category, keywords, why) {
    const matched = keywords.filter(k => joined.includes(k.toLowerCase()));
    if (matched.length > 0) {
      caps.push({
        id,
        title,
        category: category.toUpperCase(),
        confidence: matched.length > 1 ? 'HIGH' : 'MEDIUM',
        matchedKeywords: matched.slice(0, 5),
        why
      });
    }
  }

  check('CAP_NETWORK', 'Outbound Networking Capability', 'Network',
    ['wsastartup', 'connect', 'httpopenrequest', 'winhttpopen', 'internetopen', 'urldownloadtofile'],
    'Contains references to Windows network socket or HTTP communication APIs.');

  check('CAP_INJECTION', 'Process Injection / Memory Modification', 'Execution',
    ['createremotethread', 'virtualallocex', 'writeprocessmemory', 'queueuserapc', 'setthreadcontext'],
    'Contains APIs frequently used for process injection or remote memory manipulation.');

  check('CAP_PERSISTENCE', 'Persistence Installation Capability', 'Persistence',
    ['currentversion\\run', 'regsetvalueex', 'createservice', 'schtasks'],
    'Contains strings associated with auto-start registry keys, scheduled tasks, or services.');

  check('CAP_KEYLOG_INPUT', 'Input Hooking / Keystroke Capability', 'Collection',
    ['setwindowshookex', 'getasynckeystate', 'getkeystate', 'registerhotkey'],
    'Contains Windows APIs capable of capturing keyboard strokes or mouse events.');

  check('CAP_SCREEN_CAPTURE', 'Screen / Display Capture Capability', 'Collection',
    ['bitblt', 'createdc', 'createcompatiblebitmap', 'getdesktopwindow', 'printwindow'],
    'Contains graphics device context APIs capable of capturing desktop screen contents.');

  check('CAP_EVASION', 'Anti-Analysis / Debugger Evasion', 'Defense Evasion',
    ['isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess', 'outputdebugstring'],
    'Contains APIs that query for running debuggers or analysis environments.');

  check('CAP_CRYPTO_RANSOM', 'Cryptographic / Volume Tampering', 'Impact',
    ['cryptencrypt', 'bcryptencrypt', 'vssadmin delete shadows', 'bcdedit /set'],
    'Contains cryptography APIs or commands used to delete Shadow Copies.');

  if (peInfo && peInfo.packingIndicators && peInfo.packingIndicators.isPacked) {
    caps.push({
      id: 'CAP_PACKER',
      title: 'Packer / Obfuscator Detected',
      category: 'Defense Evasion',
      confidence: 'HIGH',
      matchedKeywords: peInfo.packingIndicators.packerSectionDetected ? [peInfo.packingIndicators.packerSectionDetected] : ['High section entropy'],
      why: 'One or more executable sections exhibit high Shannon entropy (>7.0) or well-known packer names.'
    });
  }

  return caps;
}

/**
 * Main Static Malware Analysis Pipeline (Isolated & Local-Only)
 */
class MalwareAnalyzer {
  /**
   * Evaluates safety restrictions before opening a target file
   */
  validateFilePath(targetPath, overrideSystemDir = false) {
    if (!targetPath || typeof targetPath !== 'string') {
      return { allowed: false, error: 'File path cannot be blank.' };
    }

    const resolved = path.resolve(targetPath);
    if (!fs.existsSync(resolved)) {
      return { allowed: false, error: `File not found at: ${resolved}` };
    }

    const stat = fs.statSync(resolved);
    if (stat.isDirectory()) {
      return { allowed: false, error: 'Path points to a directory, not a file.' };
    }

    if (stat.size > MAX_FILE_SIZE_BYTES) {
      return { allowed: false, error: `File size (${Math.round(stat.size / 1024 / 1024)} MB) exceeds static analysis budget of 100 MB.` };
    }

    // Safety guard on core Windows directories
    const lower = resolved.toLowerCase();
    for (const sysDir of RESTRICTED_SYSTEM_DIRS) {
      if (lower.startsWith(sysDir) && !overrideSystemDir) {
        return {
          allowed: false,
          requiresConfirmation: true,
          systemDirWarning: `Target file is located in protected system directory (${sysDir}). Please confirm explicitly to proceed with static inspection.`
        };
      }
    }

    return { allowed: true, resolvedPath: resolved, fileSize: stat.size };
  }

  /**
   * Executes static inspection of a local file
   */
  async analyzeFile(targetPath, options = {}) {
    const validation = this.validateFilePath(targetPath, options.overrideSystemDir);
    if (!validation.allowed) {
      return { success: false, ...validation };
    }

    const filePath = validation.resolvedPath;
    const fileName = path.basename(filePath);
    const startMs = Date.now();
    const analyzedAtUtc = new Date().toISOString();
    const reportId = crypto.randomBytes(8).toString('hex');

    // 1. Read file buffer
    const buffer = fs.readFileSync(filePath);
    const fileSize = buffer.length;

    // 2. Compute Hashes
    const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
    const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
    const md5 = crypto.createHash('md5').update(buffer).digest('hex');

    // 3. Format detection & PE Inspection
    const fileType = detectFileType(buffer);
    let peInfo = null;
    if (fileType.isPe) {
      peInfo = parsePeHeader(buffer);
    }

    // 4. Authenticode Signature Check (via persistent PowerShell worker)
    let signatureStatus = 'Unsigned / Unavailable';
    try {
      const psCmd = `(Get-AuthenticodeSignature -LiteralPath '${filePath.replace(/'/g, "''")}').Status.ToString()`;
      const sigRes = await psHost.executeCommand(psCmd, 4000);
      if (sigRes.success && sigRes.output) {
        signatureStatus = sigRes.output.trim() || 'Valid';
      }
    } catch (e) {
      signatureStatus = 'Unverified (Query timed out)';
    }

    // 5. Strings extraction (size-capped, secrets redacted)
    const strings = extractStrings(buffer);

    // 6. Passive IOC extraction
    const iocs = extractIocs(strings);

    // 7. Behavioral Capabilities
    const capabilities = inferCapabilities(strings, peInfo);

    // 8. Compile Static Report Data
    const reportData = {
      reportId,
      analyzedAtUtc,
      fileMetadata: {
        filePath,
        fileName,
        fileSize,
        fileType: fileType.type,
        mimeType: fileType.mime,
        signatureStatus
      },
      hashes: {
        sha256,
        sha1,
        md5
      },
      peStructure: peInfo,
      capabilities,
      iocs,
      stringsSample: strings.slice(0, 100),
      stringsTotalCount: strings.length,
      dynamicAnalysisInstructions: {
        safeGuidance: 'Dynamic analysis must NEVER be conducted on your host machine. If you must observe runtime execution:',
        steps: [
          '1. Set up an isolated Virtual Machine (VirtualBox or VMware Workstation).',
          '2. Set network adapter mode strictly to "Host-Only" or completely disconnected ("Not Attached").',
          '3. Disable Virtual Machine shared folders and shared clipboard.',
          '4. Take a clean VM snapshot prior to introducing any sample.',
          '5. Inside the VM, install debugging and monitoring tools: Procmon (Sysinternals), x64dbg, Ghidra, Wireshark (capturing local loopback only).',
          '6. Once finished, revert the VM to the clean snapshot.'
        ]
      },
      ghidraHandoff: {
        tool: 'Ghidra / x64dbg',
        suggestedArchitecture: peInfo ? (peInfo.is64Bit ? 'x86:LE:64:default' : 'x86:LE:32:default') : 'Auto-detect',
        entryPoint: peInfo ? peInfo.entryPointRva : 'N/A',
        imageBase: peInfo ? peInfo.imageBase : 'N/A',
        sha256
      },
      limitsDisclaimer: 'NOTICE: This is static analysis of a local file. Static analysis cannot prove runtime behavior. Obfuscation or packing may conceal actual intentions. This tool never executes the sample, never connects to extracted IOCs, and makes zero network calls.'
    };

    // 9. Compute report-level integrity hash
    const reportJson = JSON.stringify(reportData, null, 2);
    const reportIntegrityHash = crypto.createHash('sha256').update(reportJson, 'utf8').digest('hex');

    // 10. Generate printable HTML report
    const reportHtml = generateHtmlReport(reportData, reportIntegrityHash);

    // 11. Persist to SQLite
    const targetDb = options.db || db;
    const shouldPersist = options.persist !== false && (process.env.NODE_ENV !== 'test' || options.persist === true);

    if (shouldPersist && targetDb) {
      targetDb.saveMalwareReport({
        id: reportId,
        analyzedAtUtc,
        filePath,
        fileName,
        fileSize,
        hashes: reportData.hashes,
        fileType: fileType.type,
        mimeType: fileType.mime,
        isPe: fileType.isPe,
        signatureStatus,
        capabilities,
        iocs,
        integrityHash: reportIntegrityHash,
        reportJson,
        reportHtml
      });

      targetDb.recordAuditEvent('MALWARE_STATIC_ANALYSIS', 'USER', `Analyzed file ${fileName} (${sha256})`, {
        reportId,
        filePath,
        sha256,
        integrityHash: reportIntegrityHash
      });
    }

    return {
      success: true,
      reportId,
      durationMs: Date.now() - startMs,
      sha256,
      reportHash: reportIntegrityHash,
      integrityHash: reportIntegrityHash,
      data: reportData,
      reportHtml
    };
  }
}

/**
 * Generates standalone, self-contained HTML report
 */
function generateHtmlReport(data, integrityHash) {
  const meta = data.fileMetadata;
  const h = data.hashes;
  const pe = data.peStructure;

  const capsHtml = (data.capabilities || []).map(c => `
    <div style="background:#1e293b; border-left:4px solid #38bdf8; padding:0.75rem; margin-bottom:0.75rem; border-radius:4px;">
      <strong style="color:#38bdf8;">${c.title}</strong> [${c.category}] - Confidence: ${c.confidence}
      <p style="font-size:0.85rem; color:#cbd5e1; margin:0.3rem 0 0 0;">${c.why}</p>
    </div>
  `).join('') || '<p>No high-confidence behavioral capabilities inferred from static structures.</p>';

  const iocsHtml = `
    <p><strong>IPv4 Addresses (${data.iocs.ipv4.length}):</strong> ${data.iocs.ipv4.join(', ') || 'None'}</p>
    <p><strong>Domains (${data.iocs.domains.length}):</strong> ${data.iocs.domains.join(', ') || 'None'}</p>
    <p><strong>URLs (${data.iocs.urls.length}):</strong> ${data.iocs.urls.slice(0, 10).join('<br>') || 'None'}</p>
    <p><strong>Registry Keys (${data.iocs.registryKeys.length}):</strong> ${data.iocs.registryKeys.slice(0, 10).join('<br>') || 'None'}</p>
  `;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Malware Static Analysis Report - ${meta.fileName}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background:#0f172a; color:#f8fafc; margin:2rem; line-height:1.5; }
    .card { background:#1e293b; border-radius:8px; padding:1.5rem; margin-bottom:1.5rem; border:1px solid #334155; }
    h1 { color:#38bdf8; margin-top:0; }
    h2 { color:#94a3b8; border-bottom:1px solid #334155; padding-bottom:0.5rem; font-size:1.15rem; }
    .mono { font-family:Consolas, monospace; background:#0b1120; padding:0.4rem 0.6rem; border-radius:4px; word-break:break-all; }
    table { width:100%; border-collapse:collapse; margin-top:1rem; }
    th, td { text-align:left; padding:0.6rem; border-bottom:1px solid #334155; font-size:0.85rem; }
    th { color:#94a3b8; }
    .badge { display:inline-block; padding:0.2rem 0.5rem; border-radius:4px; font-size:0.75rem; font-weight:bold; }
    .badge-safe { background:#064e3b; color:#34d399; }
    .badge-warn { background:#78350f; color:#fbbf24; }
  </style>
</head>
<body>
  <h1>My Laptop Guard - Static Analysis Report</h1>
  <div class="card">
    <p><strong>File Name:</strong> ${meta.fileName}</p>
    <p><strong>File Path:</strong> <span class="mono">${meta.filePath}</span></p>
    <p><strong>File Size:</strong> ${meta.fileSize} bytes</p>
    <p><strong>File Format:</strong> ${meta.fileType}</p>
    <p><strong>Authenticode Signature:</strong> ${meta.signatureStatus}</p>
    <p><strong>SHA-256:</strong> <span class="mono">${h.sha256}</span></p>
    <p><strong>SHA-1:</strong> <span class="mono">${h.sha1}</span></p>
    <p><strong>MD5:</strong> <span class="mono">${h.md5}</span></p>
    <p><strong>Report Integrity SHA-256:</strong> <span class="mono">${integrityHash}</span></p>
  </div>

  <div class="card">
    <h2>Inferred Capabilities</h2>
    ${capsHtml}
  </div>

  <div class="card">
    <h2>Extracted IOCs (Passive - Not Verified on Network)</h2>
    ${iocsHtml}
  </div>

  ${pe ? `
  <div class="card">
    <h2>Portable Executable (PE) Structural Overview</h2>
    <p><strong>Architecture:</strong> ${pe.machine} | <strong>Subsystem:</strong> ${pe.subsystem} | <strong>Entry Point:</strong> <span class="mono">${pe.entryPointRva}</span></p>
    <p><strong>Packer Indicators:</strong> ${pe.packingIndicators.isPacked ? '<span class="badge badge-warn">POTENTIALLY PACKED</span>' : '<span class="badge badge-safe">STANDARD ENTROPY</span>'}</p>
    <table>
      <thead>
        <tr><th>Section</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th><th>Status</th></tr>
      </thead>
      <tbody>
        ${(pe.sections || []).map(s => `
          <tr>
            <td class="mono"><strong>${s.name}</strong></td>
            <td>${s.virtualSize}</td>
            <td>${s.rawSize}</td>
            <td class="mono">${s.entropy}</td>
            <td>${s.isHighEntropy ? '<span class="badge badge-warn">High Entropy (&gt;7.0)</span>' : '<span class="badge badge-safe">Normal</span>'}</td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  </div>` : ''}

  <div class="card">
    <h2>Safe Isolated Dynamic Analysis Instructions</h2>
    <ol>
      ${data.dynamicAnalysisInstructions.steps.map(s => `<li>${s.replace(/^\d+\.\s*/, '')}</li>`).join('')}
    </ol>
  </div>
</body>
</html>`;
}

// Singleton instance
const analyzer = new MalwareAnalyzer();
module.exports = analyzer;
module.exports.MalwareAnalyzer = MalwareAnalyzer;
module.exports.calculateShannonEntropy = calculateShannonEntropy;
module.exports.detectFileType = detectFileType;
module.exports.parsePeHeader = parsePeHeader;
module.exports.extractStrings = extractStrings;
module.exports.extractIocs = extractIocs;
module.exports.inferCapabilities = inferCapabilities;
