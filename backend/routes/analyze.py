import os
import re
import time
import shlex
import subprocess
from flask import Blueprint, request, jsonify, current_app, send_file
from werkzeug.utils import secure_filename

analyze_bp = Blueprint('analyze', __name__)

def parse_dpi_output(output):
    """Parse metrics from DPI engine stdout."""
    total_match = re.search(r'Total Packets:\s+(\d+)', output)
    forwarded_match = re.search(r'Forwarded:\s+(\d+)', output)
    dropped_match = re.search(r'Dropped:\s+(\d+)', output)

    return {
        'totalPackets': int(total_match.group(1)) if total_match else 0,
        'forwarded': int(forwarded_match.group(1)) if forwarded_match else 0,
        'dropped': int(dropped_match.group(1)) if dropped_match else 0
    }

def align_ascii_art(text):
    """Ensure ASCII box borders align perfectly, replicating the JS logic."""
    lines = text.splitlines()
    border_len = 0
    for line in lines:
        if line.startswith('╔') or line.startswith('╠') or line.startswith('╚'):
            border_len = max(border_len, len(line))
            
    result = []
    for line in lines:
        m = re.match(r'^(║)(.*)(║)\s*$', line)
        if m and border_len > 0:
            inner = m.group(2)
            stripped = inner.rstrip()
            pad = border_len - 2 - len(stripped)
            aligned = '║' + stripped + (' ' * pad if pad > 0 else '') + '║'
            result.append(aligned)
        else:
            result.append(line)
            
    return '\n'.join(result)

@analyze_bp.route('/api/analyze', methods=['POST'])
def analyze_pcap():
    """Handle PCAP upload and execute DPI engine."""
    if 'pcap' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['pcap']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file:
        filename = secure_filename(file.filename)
        input_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        file.save(input_path)
        
        # Generate output filename
        output_filename = f"output_{int(time.time() * 1000)}.pcap"
        output_path = os.path.join(current_app.config['UPLOAD_FOLDER'], output_filename)
        
        # Parse comma-separated rules
        rules_str = request.form.get('rules', '')
        extra_args = []
        if rules_str.strip():
            # Split by comma, trim whitespace, and ignore empty strings
            extra_args = [r.strip() for r in rules_str.split(',') if r.strip()]
            
        print(f"[DEBUG] Generated subprocess args: {extra_args}")
            
        python_script = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'packet_analyzer_py', 'main.py'))
        
        # Build command: python -X utf8 path/to/main.py <input> <output> <rules>
        args = ['python', '-X', 'utf8', python_script, input_path, output_path] + extra_args
        
        try:
            # Execute Python subprocess safely with UTF-8 encoding
            process = subprocess.run(
                args, 
                capture_output=True, 
                text=True, 
                check=False,
                encoding="utf-8",
                errors="ignore"
            )
            
            if process.returncode != 0:
                stderr_text = process.stderr.strip() if process.stderr else "Unknown error"
                print(f"Process exited with code {process.returncode}. Stderr: \n{stderr_text}")
                return jsonify({
                    'error': 'Python execution failed', 
                    'stderr': stderr_text
                }), 500
                
            stdout_data = process.stdout.strip() if process.stdout else ""
            result = parse_dpi_output(stdout_data)
            result['rawOutput'] = align_ascii_art(stdout_data)
            
            # Return downloadUrl so frontend can trigger download
            result['downloadUrl'] = f"/api/download/{output_filename}"
            
            return jsonify(result)
            
        except Exception as e:
            print('Failed to start Python process:', e)
            return jsonify({
                'error': 'Failed to start DPI engine',
                'message': str(e)
            }), 500

@analyze_bp.route('/api/download/<filename>')
def download_file(filename):
    """Allow downloading the filtered PCAP file."""
    safe_filename = secure_filename(filename)
    file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], safe_filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return jsonify({'error': 'File not found'}), 404
