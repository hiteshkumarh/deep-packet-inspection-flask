"""
Main Flask application entry point.
This replaces the old Node.js/Express server.js.
"""

import os
import sys
from flask import Flask, render_template

# Import our custom blueprint for analysis routes
from routes.analyze import analyze_bp

def create_app():
    # Base directory calculation
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    frontend_dir = os.path.abspath(os.path.join(base_dir, '..', 'frontend'))
    template_dir = os.path.join(frontend_dir, 'templates')
    static_dir = os.path.join(frontend_dir, 'static')
    
    # Initialize the Flask application
    app = Flask(__name__, static_folder=static_dir, template_folder=template_dir)

    # Validate Frontend Paths
    if not os.path.exists(template_dir):
        print(f"[ERROR] Critical: Frontend templates directory missing at {template_dir}", file=sys.stderr)
    if not os.path.exists(static_dir):
        print(f"[ERROR] Critical: Frontend static directory missing at {static_dir}", file=sys.stderr)

    # Validate DPI Engine Path
    analyzer_path = os.path.join(base_dir, 'packet_analyzer_py', 'main.py')
    if not os.path.exists(analyzer_path):
        print(f"[ERROR] Critical: DPI Engine core missing at {analyzer_path}", file=sys.stderr)

    # Ensure uploads directory exists
    UPLOAD_FOLDER = os.path.join(base_dir, 'uploads')
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    # Register the analyzer blueprint
    app.register_blueprint(analyze_bp)

    @app.route('/')
    def index():
        """Serve the frontend dashboard."""
        return render_template('index.html')

    # Startup Logging
    print("="*50)
    print("Flask Server Initialized Successfully")
    print(f"Uploads Path: {UPLOAD_FOLDER}")
    print(f"Analyzer Path: {analyzer_path}")
    print("="*50)

    return app

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    # Run the server on port 5000
    # use_reloader=False is crucial here because writing PCAP files
    # to the uploads/ directory triggers Werkzeug's file watcher,
    # causing the server to restart mid-request and dropping the connection.
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)
