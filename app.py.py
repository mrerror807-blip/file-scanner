from flask import Flask, render_template, request, jsonify, send_file, session
from flask_socketio import SocketIO, emit
import os
import hashlib
import json
import uuid
import threading
import time
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
import magic
import yara
import pefile
import base64
import logging
import concurrent.futures
from queue import Queue
from threading import Lock
import mmap
import struct

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-2gb-support'
app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024 * 1024  # 2GB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['QUARANTINE_FOLDER'] = 'quarantine'
app.config['SIGNATURES_FILE'] = 'signatures.json'
app.config['CHUNK_SIZE'] = 64 * 1024 * 1024  # 64MB chunks for processing
app.config['MAX_SCAN_TIME'] = 3600  # 1 hour max scan time
app.config['TEMP_FILE_RETENTION'] = 3600  # 1 hour

socketio = SocketIO(app, cors_allowed_origins="*", max_http_buffer_size=2 * 1024 * 1024 * 1024)

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['QUARANTINE_FOLDER'], exist_ok=True)

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('antivirus.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Thread-safe structures
scan_status = {}
status_lock = Lock()
scan_queue = Queue()
active_scans = {}

class LargeFileScanner:
    def __init__(self):
        self.signatures = self.load_signatures()
        self.yara_rules = self.compile_yara_rules()
        self.scan_history = []
        self.history_lock = Lock()
        
    def load_signatures(self):
        """Load malware signatures from JSON file"""
        if os.path.exists(app.config['SIGNATURES_FILE']):
            try:
                with open(app.config['SIGNATURES_FILE'], 'r') as f:
                    return json.load(f)
            except:
                return self.get_default_signatures()
        return self.get_default_signatures()
    
    def get_default_signatures(self):
        """Get default malware signatures"""
        return {
            'hash': {},
            'patterns': [
                b'CreateRemoteThread',
                b'WriteProcessMemory',
                b'VirtualAllocEx',
                b'GetProcAddress',
                b'LoadLibraryA',
                b'WinExec',
                b'ShellExecuteA',
                b'cmd.exe',
                b'powershell.exe',
                b'vssadmin.exe',
                b'wmic.exe',
                b'reg.exe',
                b'format.com',
                b'del.exe',
            ],
            'suspicious_strings': [
                'CreateRemoteThread',
                'WriteProcessMemory',
                'VirtualAllocEx',
                'GetProcAddress',
                'LoadLibrary',
                'WinExec',
                'ShellExecute',
                'cmd.exe',
                'powershell',
                'vssadmin',
                'wmic',
                'reg delete',
                'format',
                'del /f',
                'bitcoin',
                'stratum',
                'xmrig',
                'ransomware',
                'encrypt',
                'decrypt',
                'malware',
                'virus',
                'trojan',
                'worm',
                'backdoor',
                'keylogger',
                'spyware',
                'adware'
            ]
        }
    
    def compile_yara_rules(self):
        """Compile YARA rules for scanning"""
        rules_source = """
        rule SuspiciousImports {
            strings:
                $a = "CreateRemoteThread" nocase
                $b = "WriteProcessMemory" nocase
                $c = "VirtualAllocEx" nocase
                $d = "GetProcAddress" nocase
                $e = "LoadLibraryA" nocase
                $f = "WinExec" nocase
                $g = "ShellExecuteA" nocase
            condition:
                2 of them
        }
        
        rule PackedExecutable {
            strings:
                $s1 = ".UPX0" nocase
                $s2 = ".UPX1" nocase
                $s3 = ".UPX2" nocase
                $s4 = "UPX!" nocase
                $s5 = ".packed" nocase
                $s6 = ".themida" nocase
                $s7 = ".vmp0" nocase
            condition:
                any of them
        }
        
        rule Cryptominer {
            strings:
                $s1 = "stratum+tcp" nocase
                $s2 = "xmr" nocase
                $s3 = "cryptonight" nocase
                $s4 = "minerd" nocase
                $s5 = "xmrig" nocase
                $s6 = "pool" nocase
                $s7 = "monero" nocase
            condition:
                3 of them
        }
        
        rule Ransomware {
            strings:
                $s1 = "encrypt" nocase
                $s2 = "decrypt" nocase
                $s3 = "ransom" nocase
                $s4 = "bitcoin" nocase
                $s5 = "payment" nocase
                $s6 = ".crypt" nocase
                $s7 = ".locked" nocase
                $s8 = "README" nocase
            condition:
                3 of them
        }
        
        rule Keylogger {
            strings:
                $s1 = "GetAsyncKeyState" nocase
                $s2 = "SetWindowsHookEx" nocase
                $s3 = "keylogger" nocase
                $s4 = "keystroke" nocase
                $s5 = "log.txt" nocase
            condition:
                2 of them
        }
        
        rule AntiDebug {
            strings:
                $s1 = "IsDebuggerPresent" nocase
                $s2 = "CheckRemoteDebuggerPresent" nocase
                $s3 = "NtQueryInformationProcess" nocase
                $s4 = "OutputDebugString" nocase
            condition:
                2 of them
        }
        """
        
        try:
            return yara.compile(source=rules_source)
        except Exception as e:
            logger.error(f"Error compiling YARA rules: {e}")
            return None
    
    def calculate_hashes_chunked(self, filepath, scan_id):
        """Calculate multiple hashes of a large file using chunks"""
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }
        
        try:
            file_size = os.path.getsize(filepath)
            processed = 0
            
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(app.config['CHUNK_SIZE'])
                    if not chunk:
                        break
                    
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
                    
                    processed += len(chunk)
                    progress = (processed / file_size) * 100
                    
                    with status_lock:
                        if scan_id in scan_status:
                            scan_status[scan_id]['hash_progress'] = progress
                            scan_status[scan_id]['message'] = f"হ্যাশ ক্যালকুলেশন: {progress:.1f}%"
                    
                    socketio.emit('scan_update', {
                        'scan_id': scan_id,
                        'progress': progress,
                        'stage': 'hash',
                        'message': f"হ্যাশ ক্যালকুলেশন: {progress:.1f}%"
                    })
            
            return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
            
        except Exception as e:
            logger.error(f"Error calculating hashes for {filepath}: {e}")
            return None
    
    def quick_scan(self, filepath, scan_id):
        """Quick scan of file headers and first few MB"""
        threats = []
        
        try:
            file_size = os.path.getsize(filepath)
            
            # Check file signature/magic bytes
            with open(filepath, 'rb') as f:
                header = f.read(64)  # Read first 64 bytes
                
                # Check for executable signatures
                if header.startswith(b'MZ'):
                    threats.append({
                        'type': 'file_signature',
                        'threat': 'Windows Executable detected',
                        'details': ['File has MZ header - Windows executable']
                    })
                    
                    # Check for PE signature at offset 0x3C
                    f.seek(0x3C)
                    pe_offset_bytes = f.read(4)
                    if len(pe_offset_bytes) == 4:
                        pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
                        f.seek(pe_offset)
                        pe_signature = f.read(4)
                        if pe_signature == b'PE\x00\x00':
                            threats.append({
                                'type': 'file_signature',
                                'threat': 'Valid PE file',
                                'details': ['File is a valid Portable Executable']
                            })
                
                # Check for script signatures
                elif header.startswith(b'#!'):
                    threats.append({
                        'type': 'file_signature',
                        'threat': 'Script file detected',
                        'details': ['File is a script with shebang']
                    })
                
                # Check for PDF signature
                elif header.startswith(b'%PDF'):
                    threats.append({
                        'type': 'file_signature',
                        'threat': 'PDF file detected',
                        'details': ['File is a PDF document']
                    })
            
            # Quick entropy check on first few MB
            with open(filepath, 'rb') as f:
                sample = f.read(min(10 * 1024 * 1024, file_size))  # First 10MB
                entropy = self.calculate_entropy(sample)
                
                if entropy > 7.0:
                    threats.append({
                        'type': 'entropy',
                        'threat': 'High entropy',
                        'details': [f'Entropy: {entropy:.2f} - Possible packed/encrypted content']
                    })
            
            with status_lock:
                if scan_id in scan_status:
                    scan_status[scan_id]['quick_scan_done'] = True
            
            return threats
            
        except Exception as e:
            logger.error(f"Quick scan error: {e}")
            return threats
    
    def signature_scan_chunked(self, filepath, scan_id):
        """Signature-based scanning of large file"""
        threats = []
        
        try:
            file_size = os.path.getsize(filepath)
            processed = 0
            chunk_num = 0
            
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(app.config['CHUNK_SIZE'])
                    if not chunk:
                        break
                    
                    # Check for patterns in this chunk
                    for pattern in self.signatures.get('patterns', []):
                        if pattern in chunk:
                            threats.append({
                                'type': 'pattern_match',
                                'threat': f'Suspicious pattern found',
                                'details': [f'Pattern: {pattern[:50]}... at offset {processed}']
                            })
                    
                    processed += len(chunk)
                    chunk_num += 1
                    
                    # Update progress every 10 chunks
                    if chunk_num % 10 == 0:
                        progress = (processed / file_size) * 100
                        with status_lock:
                            if scan_id in scan_status:
                                scan_status[scan_id]['signature_progress'] = progress
                        
                        socketio.emit('scan_update', {
                            'scan_id': scan_id,
                            'progress': progress,
                            'stage': 'signature',
                            'message': f"সিগনেচার স্ক্যান: {progress:.1f}%"
                        })
            
            return threats
            
        except Exception as e:
            logger.error(f"Signature scan error: {e}")
            return threats
    
    def yara_scan_chunked(self, filepath, scan_id):
        """YARA scanning of large file"""
        if not self.yara_rules:
            return []
        
        threats = []
        
        try:
            # YARA can handle large files efficiently
            matches = self.yara_rules.match(filepath)
            
            if matches:
                for match in matches:
                    threats.append({
                        'type': 'yara',
                        'threat': f'YARA Rule Match: {match.rule}',
                        'details': [f'Matched rule: {match.rule}']
                    })
            
            with status_lock:
                if scan_id in scan_status:
                    scan_status[scan_id]['yara_done'] = True
            
            socketio.emit('scan_update', {
                'scan_id': scan_id,
                'progress': 100,
                'stage': 'yara',
                'message': "YARA স্ক্যান সম্পন্ন"
            })
            
        except Exception as e:
            logger.error(f"YARA scan error: {e}")
        
        return threats
    
    def heuristic_scan_chunked(self, filepath, scan_id):
        """Heuristic scanning of large file"""
        threats = []
        total_score = 0
        details = []
        
        try:
            file_size = os.path.getsize(filepath)
            
            # Check file size
            if file_size < 1024:
                total_score += 10
                details.append(f"Unusually small file: {file_size} bytes")
            elif file_size > 500 * 1024 * 1024:  # > 500MB
                total_score += 15
                details.append(f"Large file: {file_size / (1024*1024):.2f} MB")
            
            # Sample-based scanning
            suspicious_count = 0
            total_chunks = 0
            
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(app.config['CHUNK_SIZE'])
                    if not chunk:
                        break
                    
                    total_chunks += 1
                    
                    # Check for suspicious strings in this chunk
                    for pattern in self.signatures['suspicious_strings']:
                        if pattern.encode() in chunk:
                            suspicious_count += 1
                    
                    # Calculate entropy for this chunk
                    chunk_entropy = self.calculate_entropy(chunk)
                    if chunk_entropy > 7.0:
                        total_score += 5
                        details.append(f"High entropy chunk detected: {chunk_entropy:.2f}")
            
            # Calculate overall threat level
            if suspicious_count > 10:
                total_score += 30
                details.append(f"Multiple suspicious strings found: {suspicious_count}")
            elif suspicious_count > 5:
                total_score += 20
                details.append(f"Several suspicious strings found: {suspicious_count}")
            elif suspicious_count > 0:
                total_score += 10
                details.append(f"Some suspicious strings found: {suspicious_count}")
            
            if total_score >= 50:
                threats.append({
                    'type': 'heuristic',
                    'threat': 'High',
                    'score': total_score,
                    'details': details
                })
            elif total_score >= 30:
                threats.append({
                    'type': 'heuristic',
                    'threat': 'Medium',
                    'score': total_score,
                    'details': details
                })
            elif total_score >= 15:
                threats.append({
                    'type': 'heuristic',
                    'threat': 'Low',
                    'score': total_score,
                    'details': details
                })
            
            with status_lock:
                if scan_id in scan_status:
                    scan_status[scan_id]['heuristic_done'] = True
            
            socketio.emit('scan_update', {
                'scan_id': scan_id,
                'progress': 100,
                'stage': 'heuristic',
                'message': "হিউরিস্টিক স্ক্যান সম্পন্ন"
            })
            
        except Exception as e:
            logger.error(f"Heuristic scan error: {e}")
        
        return threats
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for i in range(256):
            freq = data.count(i) / len(data)
            if freq > 0:
                entropy -= freq * (freq.bit_length() - 1)
        
        return entropy
    
    def scan_large_file(self, filepath, scan_id):
        """Complete scan of large file using multiple methods"""
        try:
            file_size = os.path.getsize(filepath)
            
            # Initialize scan status
            with status_lock:
                scan_status[scan_id] = {
                    'status': 'scanning',
                    'progress': 0,
                    'file_name': os.path.basename(filepath),
                    'file_size': file_size,
                    'start_time': time.time(),
                    'stages': {}
                }
            
            socketio.emit('scan_started', {'scan_id': scan_id})
            
            # Quick scan first
            quick_threats = self.quick_scan(filepath, scan_id)
            
            # Calculate hashes (parallel)
            file_hashes = self.calculate_hashes_chunked(filepath, scan_id)
            
            # Check hash signatures
            hash_threats = []
            if file_hashes:
                for hash_type, hash_value in file_hashes.items():
                    if hash_value in self.signatures['hash']:
                        hash_threats.append({
                            'type': 'signature',
                            'threat': self.signatures['hash'][hash_value],
                            'hash_type': hash_type,
                            'hash_value': hash_value
                        })
            
            # Parallel scanning of different methods
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                # Submit scanning tasks
                signature_future = executor.submit(self.signature_scan_chunked, filepath, scan_id)
                yara_future = executor.submit(self.yara_scan_chunked, filepath, scan_id)
                heuristic_future = executor.submit(self.heuristic_scan_chunked, filepath, scan_id)
                
                # Get results
                signature_threats = signature_future.result(timeout=app.config['MAX_SCAN_TIME'])
                yara_threats = yara_future.result(timeout=app.config['MAX_SCAN_TIME'])
                heuristic_threats = heuristic_future.result(timeout=app.config['MAX_SCAN_TIME'])
            
            # Combine all threats
            all_threats = []
            all_threats.extend(quick_threats)
            all_threats.extend(hash_threats)
            all_threats.extend(signature_threats)
            all_threats.extend(yara_threats)
            all_threats.extend(heuristic_threats)
            
            # PE analysis for executables
            if filepath.lower().endswith(('.exe', '.dll', '.scr', '.ocx', '.sys')):
                pe_threats = self.analyze_pe_file(filepath)
                if pe_threats:
                    all_threats.extend(pe_threats)
            
            # Determine risk level
            risk_level = self.calculate_risk_level(all_threats)
            
            # Create scan result
            scan_result = {
                'scan_id': scan_id,
                'file_name': os.path.basename(filepath),
                'file_size': file_size,
                'file_type': magic.from_file(filepath, mime=True),
                'hashes': file_hashes,
                'threats': all_threats,
                'scan_time': datetime.now().isoformat(),
                'risk_level': risk_level,
                'scan_duration': time.time() - scan_status[scan_id]['start_time']
            }
            
            # Add to history
            with self.history_lock:
                self.scan_history.append(scan_result)
                # Keep last 100 scans
                if len(self.scan_history) > 100:
                    self.scan_history = self.scan_history[-100:]
            
            # Update status
            with status_lock:
                scan_status[scan_id]['status'] = 'completed'
                scan_status[scan_id]['result'] = scan_result
            
            socketio.emit('scan_completed', {
                'scan_id': scan_id,
                'result': scan_result
            })
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Scan error for {filepath}: {e}")
            
            with status_lock:
                if scan_id in scan_status:
                    scan_status[scan_id]['status'] = 'error'
                    scan_status[scan_id]['error'] = str(e)
            
            socketio.emit('scan_error', {
                'scan_id': scan_id,
                'error': str(e)
            })
            
            return None
    
    def analyze_pe_file(self, filepath):
        """Analyze PE file structure"""
        threats = []
        
        try:
            pe = pefile.PE(filepath)
            
            # Check for suspicious imports
            suspicious_apis = [
                'CreateRemoteThread', 'WriteProcessMemory',
                'VirtualAllocEx', 'SetWindowsHookEx',
                'GetProcAddress', 'LoadLibraryA',
                'WinExec', 'ShellExecuteA', 'RegSetValue',
                'CryptEncrypt', 'CryptDecrypt'
            ]
            
            found_apis = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name and imp.name.decode() in suspicious_apis:
                            found_apis.append(imp.name.decode())
            
            if found_apis:
                threats.append({
                    'type': 'pe_analysis',
                    'threat': 'Suspicious API calls',
                    'details': [f'Found {len(found_apis)} suspicious APIs'],
                    'apis': found_apis[:10]  # First 10
                })
            
            # Check for packed sections
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                entropy = section.get_entropy()
                
                if entropy > 7.0:
                    threats.append({
                        'type': 'pe_analysis',
                        'threat': 'Packed section detected',
                        'details': [
                            f'Section: {section_name}',
                            f'Entropy: {entropy:.2f}',
                            f'Size: {section.SizeOfRawData} bytes'
                        ]
                    })
                
                # Check for suspicious section names
                suspicious_sections = ['.UPX', '.packed', '.themida', '.vmp']
                if any(sus in section_name for sus in suspicious_sections):
                    threats.append({
                        'type': 'pe_analysis',
                        'threat': 'Suspicious section name',
                        'details': [f'Section: {section_name}']
                    })
            
            # Check for TLS callbacks (often used by malware)
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                threats.append({
                    'type': 'pe_analysis',
                    'threat': 'TLS callbacks present',
                    'details': ['May indicate anti-debugging or stealth techniques']
                })
            
            # Check for resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                resource_count = len(pe.DIRECTORY_ENTRY_RESOURCE.entries)
                if resource_count > 50:
                    threats.append({
                        'type': 'pe_analysis',
                        'threat': 'Many resources',
                        'details': [f'Contains {resource_count} resources']
                    })
            
        except Exception as e:
            logger.error(f"PE analysis error: {e}")
        
        return threats
    
    def calculate_risk_level(self, threats):
        """Calculate overall risk level"""
        if not threats:
            return 'Clean'
        
        high_count = sum(1 for t in threats if t.get('threat') in ['High', 'YARA Rule Match: SuspiciousImports', 'YARA Rule Match: Ransomware'])
        medium_count = sum(1 for t in threats if t.get('threat') == 'Medium')
        
        if high_count > 0:
            return 'High'
        elif medium_count > 0:
            return 'Medium'
        elif threats:
            return 'Low'
        
        return 'Clean'
    
    def quarantine_file(self, filepath, scan_result):
        """Move file to quarantine"""
        try:
            filename = secure_filename(os.path.basename(filepath))
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_filename = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(app.config['QUARANTINE_FOLDER'], quarantine_filename)
            
            # Copy file to quarantine
            import shutil
            shutil.copy2(filepath, quarantine_path)
            
            # Save scan result
            result_path = quarantine_path + '.json'
            with open(result_path, 'w') as f:
                json.dump(scan_result, f, indent=2)
            
            logger.info(f"File quarantined: {quarantine_filename}")
            return quarantine_filename
            
        except Exception as e:
            logger.error(f"Quarantine error: {e}")
            return None
    
    def cleanup_old_files(self):
        """Clean up old temporary files"""
        now = time.time()
        
        # Clean upload folder
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.isfile(filepath):
                file_age = now - os.path.getctime(filepath)
                if file_age > app.config['TEMP_FILE_RETENTION']:
                    try:
                        os.remove(filepath)
                        logger.info(f"Removed old temp file: {filename}")
                    except:
                        pass

# Initialize scanner
scanner = LargeFileScanner()

# Start cleanup thread
def cleanup_task():
    while True:
        time.sleep(3600)  # Run every hour
        scanner.cleanup_old_files()

cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
cleanup_thread.start()

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan_file():
    """Handle file upload and scanning"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Check file size
    if request.content_length > app.config['MAX_CONTENT_LENGTH']:
        return jsonify({'error': 'File too large (max 2GB)'}), 400
    
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())
    
    # Save uploaded file
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{scan_id}_{filename}")
    
    # Save file in chunks to handle large files
    chunk_size = 8 * 1024 * 1024  # 8MB chunks
    with open(filepath, 'wb') as f:
        while True:
            chunk = file.stream.read(chunk_size)
            if not chunk:
                break
            f.write(chunk)
    
    # Start scan in background thread
    thread = threading.Thread(target=scanner.scan_large_file, args=(filepath, scan_id))
    thread.daemon = True
    thread.start()
    
    active_scans[scan_id] = {
        'filepath': filepath,
        'thread': thread,
        'start_time': time.time()
    }
    
    return jsonify({
        'scan_id': scan_id,
        'message': 'Scan started',
        'file_name': filename
    })

@app.route('/scan/status/<scan_id>')
def get_scan_status(scan_id):
    """Get scan status"""
    with status_lock:
        if scan_id in scan_status:
            return jsonify(scan_status[scan_id])
    return jsonify({'error': 'Scan not found'}), 404

@app.route('/scan/result/<scan_id>')
def get_scan_result(scan_id):
    """Get scan result"""
    with status_lock:
        if scan_id in scan_status and 'result' in scan_status[scan_id]:
            return jsonify(scan_status[scan_id]['result'])
    return jsonify({'error': 'Result not found'}), 404

@app.route('/quarantine', methods=['POST'])
def quarantine_file():
    """Move scanned file to quarantine"""
    data = request.json
    if not data or 'scan_id' not in data:
        return jsonify({'error': 'Invalid request'}), 400
    
    scan_id = data['scan_id']
    
    with status_lock:
        if scan_id in scan_status and 'result' in scan_status[scan_id]:
            result = scan_status[scan_id]['result']
            filepath = active_scans.get(scan_id, {}).get('filepath')
            
            if filepath and os.path.exists(filepath):
                quarantine_name = scanner.quarantine_file(filepath, result)
                
                if quarantine_name:
                    return jsonify({
                        'success': True,
                        'quarantine_name': quarantine_name,
                        'message': 'File quarantined successfully'
                    })
    
    return jsonify({'error': 'Failed to quarantine file'}), 500

@app.route('/history')
def get_history():
    """Get scan history"""
    with scanner.history_lock:
        return jsonify(scanner.scan_history)

@app.route('/stats')
def get_stats():
    """Get scanning statistics"""
    with scanner.history_lock:
        total_scans = len(scanner.scan_history)
        threats_found = sum(1 for scan in scanner.scan_history if scan['threats'])
        clean_files = total_scans - threats_found
        
        return jsonify({
            'total_scans': total_scans,
            'threats_found': threats_found,
            'clean_files': clean_files,
            'active_scans': len(active_scans)
        })

@app.route('/cancel/<scan_id>', methods=['POST'])
def cancel_scan(scan_id):
    """Cancel an ongoing scan"""
    if scan_id in active_scans:
        # Mark as cancelled
        with status_lock:
            if scan_id in scan_status:
                scan_status[scan_id]['status'] = 'cancelled'
        
        socketio.emit('scan_cancelled', {'scan_id': scan_id})
        return jsonify({'success': True, 'message': 'Scan cancelled'})
    
    return jsonify({'error': 'Scan not found'}), 404

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    emit('connected', {'data': 'Connected to antivirus scanner'})

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    pass

# Error handlers
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large (max 2GB)'}), 413

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, max_http_buffer_size=2 * 1024 * 1024 * 1024)