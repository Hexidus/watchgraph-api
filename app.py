from flask import Flask, jsonify
from datetime import datetime
import os

app = Flask(__name__)

@app.route('/')
def home():
    """Main endpoint for WatchGraph continuous AI compliance monitoring"""
    return jsonify({
        "message": "Hello from WatchGraph - Continuous AI Compliance Monitoring Platform",
        "company": "Hexidus",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
        "description": "Real-time monitoring and compliance checking for AI systems"
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "WatchGraph API",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime": "operational"
    })

@app.route('/version')
def version():
    """Version information endpoint"""
    return jsonify({
        "service": "WatchGraph",
        "version": "1.0.0",
        "platform": "Continuous AI Compliance Monitoring",
        "company": "Hexidus",
        "environment": "development"
    })

@app.route('/api/systems')
def systems():
    """Future endpoint for AI system registration and monitoring"""
    return jsonify({
        "message": "AI Systems endpoint - Coming soon",
        "description": "Register and monitor AI systems for compliance",
        "status": "under_development"
    })

@app.route('/api/compliance')
def compliance():
    """Future endpoint for compliance rule management"""
    return jsonify({
        "message": "Compliance Rules endpoint - Coming soon", 
        "description": "Define and manage compliance rules for AI systems",
        "status": "under_development"
    })

if __name__ == '__main__':
    # Use PORT environment variable for Azure App Service
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
