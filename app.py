#!/usr/bin/env python3
# Advanced Recon Tool - Backend
# Integrates with Hunter.io, Shodan.io, and Gemini AI for comprehensive reconnaissance

import subprocess
import os
import json
import requests
import time
import argparse
import logging
import threading
import queue
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import shodan
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)  # Enable CORS for all routes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# API Keys (load from environment variables)
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
HUNTER_API_KEY = os.getenv('HUNTER_API_KEY')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')

# Configure Gemini AI
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# Global queue for scan results
scan_results_queue = queue.Queue()

# Directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(BASE_DIR, "recon-output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Initialize Shodan API client if key is available
shodan_api = None
if SHODAN_API_KEY:
    shodan_api = shodan.Shodan(SHODAN_API_KEY)

# Tool executor with live output + logging
def run_and_log(tool, description, command, report_file, result_queue=None):
    header = f"\n\n{'='*80}\n### {tool.upper()} - {description}\n{'='*80}\n$ {' '.join(command)}\n"
    
    with open(report_file, 'a', encoding='utf-8') as f:
        f.write(header)
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output = []
            
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                clean_line = line.strip()
                output.append(clean_line)
                f.write(line)
            
            process.wait()
            
            if result_queue:
                result_queue.put({
                    "tool": tool,
                    "description": description,
                    "command": " ".join(command),
                    "output": output
                })
                
            return output
        except Exception as e:
            error_msg = f"[ERROR] {tool} failed: {str(e)}"
            f.write(f"{error_msg}\n")
            logger.error(error_msg)
            
            if result_queue:
                result_queue.put({
                    "tool": tool,
                    "description": description,
                    "command": " ".join(command),
                    "error": str(e)
                })
            
            return []

# Hunter.io API integration
def hunter_domain_search(domain, api_key, report_file):
    if not api_key:
        logger.warning("Hunter.io API key not provided. Skipping Hunter.io reconnaissance.")
        return {"error": "Hunter.io API key not provided"}
    
    hunter_url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    
    with open(report_file, 'a', encoding='utf-8') as f:
        header = f"\n\n{'='*80}\n### HUNTER.IO - Email Reconnaissance\n{'='*80}\n"
        f.write(header)
        
        try:
            response = requests.get(hunter_url)
            data = response.json()
            
            if response.status_code == 200:
                f.write(f"Domain: {domain}\n")
                f.write(f"Found {data['meta']['results']} email addresses\n\n")
                
                if data['data']['emails']:
                    f.write("Email Addresses:\n")
                    for email in data['data']['emails']:
                        f.write(f"- {email['value']} (Confidence: {email['confidence']}%)\n")
                        if email.get('position'):
                            f.write(f"  Position: {email['position']}\n")
                        if email.get('first_name') and email.get('last_name'):
                            f.write(f"  Name: {email['first_name']} {email['last_name']}\n")
                
                return data
            else:
                error_msg = f"Hunter.io API Error: {data.get('errors', ['Unknown error'])[0]}"
                f.write(f"{error_msg}\n")
                logger.error(error_msg)
                return {"error": error_msg}
                
        except Exception as e:
            error_msg = f"Hunter.io API request failed: {str(e)}"
            f.write(f"{error_msg}\n")
            logger.error(error_msg)
            return {"error": error_msg}

# Shodan.io API integration
def shodan_host_search(target, api_key, report_file):
    if not api_key:
        logger.warning("Shodan API key not provided. Skipping Shodan reconnaissance.")
        return {"error": "Shodan API key not provided"}
    
    api = shodan.Shodan(api_key)
    
    with open(report_file, 'a', encoding='utf-8') as f:
        header = f"\n\n{'='*80}\n### SHODAN.IO - Host Information\n{'='*80}\n"
        f.write(header)
        
        try:
            # Check if input is an IP or domain
            if not target.replace('.', '').isdigit():
                # It's a domain, try to resolve it
                import socket
                try:
                    ip = socket.gethostbyname(target)
                    f.write(f"Resolved {target} to IP: {ip}\n\n")
                    target = ip
                except socket.gaierror:
                    error_msg = f"Could not resolve hostname {target}"
                    f.write(f"{error_msg}\n")
                    logger.error(error_msg)
                    return {"error": error_msg}
            
            # Query Shodan
            results = api.host(target)
            
            # Write summary information
            f.write(f"IP: {results.get('ip_str', 'N/A')}\n")
            f.write(f"Organization: {results.get('org', 'N/A')}\n")
            f.write(f"Operating System: {results.get('os', 'N/A')}\n")
            f.write(f"Country: {results.get('country_name', 'N/A')}\n")
            f.write(f"City: {results.get('city', 'N/A')}\n")
            f.write(f"ISP: {results.get('isp', 'N/A')}\n")
            f.write(f"Last Update: {results.get('last_update', 'N/A')}\n")
            f.write(f"Hostnames: {', '.join(results.get('hostnames', ['N/A']))}\n")
            f.write(f"Domains: {', '.join(results.get('domains', ['N/A']))}\n\n")
            
            # Write open ports
            if 'ports' in results:
                f.write(f"Open Ports: {', '.join(map(str, results['ports']))}\n\n")
            
            # Write services details
            if 'data' in results:
                f.write("Services:\n")
                for service in results['data']:
                    f.write(f"- Port: {service.get('port', 'N/A')}\n")
                    f.write(f"  Protocol: {service.get('transport', 'N/A')}\n")
                    f.write(f"  Banner: {service.get('data', 'N/A')[:100]}...\n\n")
            
            # Write vulnerabilities if any
            if 'vulns' in results:
                f.write("Vulnerabilities:\n")
                for vuln in results['vulns']:
                    f.write(f"- {vuln}\n")
            
            return results
            
        except shodan.APIError as e:
            error_msg = f"Shodan API Error: {str(e)}"
            f.write(f"{error_msg}\n")
            logger.error(error_msg)
            return {"error": error_msg}
        except Exception as e:
            error_msg = f"Shodan request failed: {str(e)}"
            f.write(f"{error_msg}\n")
            logger.error(error_msg)
            return {"error": error_msg}

# Gemini AI analysis integration
def analyze_with_gemini(report_file):
    if not GEMINI_API_KEY:
        logger.warning("Gemini API key not provided. Skipping AI analysis.")
        return {"error": "Gemini API key not provided"}
    
    try:
        # Read the report content
        with open(report_file, 'r', encoding='utf-8') as f:
            report_content = f.read()
        
        # Set up the model
        model = genai.GenerativeModel('gemini-pro')
        
        # Create a prompt for analysis
        prompt = f"""
        Analyze the following reconnaissance data and provide a comprehensive security assessment:
        
        {report_content[:100000]}  # Only sending the first 100k characters to stay within token limits
        
        Please provide:
        1. A summary of key findings
        2. Identified vulnerabilities and their severity (Critical, High, Medium, Low)
        3. Exposed services and potential security implications
        4. Recommendations for security improvements
        5. Overall risk assessment
        """
        
        # Generate the response
        response = model.generate_content(prompt)
        
        # Write the AI analysis to the report
        with open(report_file, 'a', encoding='utf-8') as f:
            f.write("\n\n" + "="*80 + "\n")
            f.write("### GEMINI AI - Security Analysis & Recommendations\n")
            f.write("="*80 + "\n\n")
            f.write(response.text)
        
        return {"analysis": response.text}
        
    except Exception as e:
        error_msg = f"Gemini AI analysis failed: {str(e)}"
        logger.error(error_msg)
        
        # Still write the error to the report
        with open(report_file, 'a', encoding='utf-8') as f:
            f.write("\n\n" + "="*80 + "\n")
            f.write("### GEMINI AI - Security Analysis & Recommendations\n")
            f.write("="*80 + "\n\n")
            f.write(f"Error: {error_msg}")
        
        return {"error": error_msg}

# Run reconnaissance tasks in parallel
def run_recon_task(task_function, *args):
    try:
        return task_function(*args)
    except Exception as e:
        logger.error(f"Task failed: {str(e)}")
        return {"error": str(e)}

# Main reconnaissance process
def run_recon(target, options):
    if not target:
        return {"error": "No target provided"}
    
    target = target.strip()
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_name = f"{target.replace('.', '_')}_{timestamp}_FULL_RECON.txt"
    report_file = os.path.join(OUTPUT_DIR, report_name)
    
    # Initialize report file
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(f"Advanced Reconnaissance Report for {target}\n")
        f.write(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*80 + "\n\n")
    
    # Track all scan results
    all_results = []
    
    # Run Nmap scans
    if options.get('nmap', True):
        all_results.append(run_and_log("Nmap", "Top 1000 Ports", ["nmap", target], report_file, scan_results_queue))
        all_results.append(run_and_log("Nmap", "Full TCP Ports", ["nmap", "-p-", target], report_file, scan_results_queue))
        all_results.append(run_and_log("Nmap", "Service Detection", ["nmap", "-sV", target], report_file, scan_results_queue))
        all_results.append(run_and_log("Nmap", "OS Detection", ["nmap", "-O", target], report_file, scan_results_queue))
        all_results.append(run_and_log("Nmap", "Script Scan (vuln)", ["nmap", "--script", "vuln", target], report_file, scan_results_queue))
        all_results.append(run_and_log("Nmap", "UDP Scan", ["nmap", "-sU", "-T4", target], report_file, scan_results_queue))
    
    # Run DNS Recon
    if options.get('dns', True):
        all_results.append(run_and_log("dnsenum", "Standard Scan", ["dnsenum", target], report_file, scan_results_queue))
        all_results.append(run_and_log("dnsrecon", "Default Mode", ["dnsrecon", "-d", target], report_file, scan_results_queue))
    
    # Run Subdomain Recon
    if options.get('subdomains', True):
        all_results.append(run_and_log("sublist3r", "Passive", ["sublist3r", "-d", target], report_file, scan_results_queue))
        all_results.append(run_and_log("amass", "Passive Enum", ["amass", "enum", "-passive", "-d", target], report_file, scan_results_queue))
        all_results.append(run_and_log("amass", "Brute Force Enum", ["amass", "enum", "-brute", "-d", target], report_file, scan_results_queue))
    
    # Run Web Recon
    if options.get('web', True):
        all_results.append(run_and_log("whatweb", "Tech Fingerprinting", ["whatweb", target], report_file, scan_results_queue))
        all_results.append(run_and_log("nikto", "Default Web Scan", ["nikto", "-host", target], report_file, scan_results_queue))
        all_results.append(run_and_log("wafw00f", "WAF Detection", ["wafw00f", target], report_file, scan_results_queue))
        all_results.append(run_and_log("gobuster", "Directory Bruteforce", [
            "gobuster", "dir", "-u", f"http://{target}", "-w", "/usr/share/wordlists/dirb/common.txt"
        ], report_file, scan_results_queue))
        all_results.append(run_and_log("dirsearch", "Full Web Scan", [
            "dirsearch", "-u", f"http://{target}", "-e", "php,html,js"
        ], report_file, scan_results_queue))
    
    # Run OSINT
    if options.get('osint', True):
        all_results.append(run_and_log("theHarvester", "All Sources", ["theHarvester", "-d", target, "-b", "all"], report_file, scan_results_queue))
    
    # Run Port Scanners
    if options.get('ports', True):
        all_results.append(run_and_log("masscan", "Full TCP Range", ["masscan", target, "-p1-65535", "--rate=1000"], report_file, scan_results_queue))
        all_results.append(run_and_log("rustscan", "Fast Recon", ["rustscan", "-a", target, "--ulimit", "5000"], report_file, scan_results_queue))
    
    # Run SSL / SMB
    if options.get('ssl_smb', True):
        all_results.append(run_and_log("sslscan", "SSL Security", ["sslscan", target], report_file, scan_results_queue))
        all_results.append(run_and_log("smbclient", "Anonymous SMB Share", ["smbclient", f"//{target}/share", "-N"], report_file, scan_results_queue))
    
    # Run Hunter.io API query
    if options.get('hunter', True) and HUNTER_API_KEY:
        hunter_results = hunter_domain_search(target, HUNTER_API_KEY, report_file)
        scan_results_queue.put({
            "tool": "Hunter.io",
            "description": "Email Reconnaissance",
            "output": hunter_results
        })
    
    # Run Shodan.io API query
    if options.get('shodan', True) and SHODAN_API_KEY:
        shodan_results = shodan_host_search(target, SHODAN_API_KEY, report_file)
        scan_results_queue.put({
            "tool": "Shodan.io",
            "description": "Host Information",
            "output": shodan_results
        })
    
    # Run Gemini AI analysis if enabled
    if options.get('gemini', True) and GEMINI_API_KEY:
        gemini_analysis = analyze_with_gemini(report_file)
        scan_results_queue.put({
            "tool": "Gemini AI",
            "description": "Security Analysis",
            "output": gemini_analysis
        })
    
    return {
        "status": "completed",
        "report_file": report_name,
        "target": target,
        "timestamp": timestamp
    }

# API Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    options = data.get('options', {})
    
    if not target:
        return jsonify({"error": "No target specified"}), 400
    
    # Clear the queue before starting a new scan
    while not scan_results_queue.empty():
        try:
            scan_results_queue.get_nowait()
        except queue.Empty:
            break
    
    # Start scan in a separate thread
    scan_thread = threading.Thread(target=run_recon, args=(target, options))
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({
        "status": "started",
        "target": target,
        "message": "Scan started successfully"
    })

@app.route('/api/status', methods=['GET'])
def scan_status():
    results = []
    
    # Get all results from the queue without blocking
    while not scan_results_queue.empty():
        try:
            result = scan_results_queue.get_nowait()
            results.append(result)
        except queue.Empty:
            break
    
    return jsonify({
        "status": "running" if results else "idle",
        "results": results
    })

@app.route('/api/reports', methods=['GET'])
def list_reports():
    reports = []
    for filename in os.listdir(OUTPUT_DIR):
        if filename.endswith('_FULL_RECON.txt'):
            file_path = os.path.join(OUTPUT_DIR, filename)
            file_size = os.path.getsize(file_path)
            file_time = os.path.getmtime(file_path)
            
            parts = filename.split('_')
            target = parts[0].replace('_', '.')
            
            reports.append({
                "filename": filename,
                "target": target,
                "size": file_size,
                "timestamp": datetime.fromtimestamp(file_time).strftime('%Y-%m-%d %H:%M:%S')
            })
    
    return jsonify({"reports": sorted(reports, key=lambda x: x["timestamp"], reverse=True)})

@app.route('/api/reports/<filename>', methods=['GET'])
def get_report(filename):
    file_path = os.path.join(OUTPUT_DIR, filename)
    
    if not os.path.exists(file_path):
        return jsonify({"error": "Report not found"}), 404
    
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)

@app.route('/api/check', methods=['GET'])
def check_api_keys():
    return jsonify({
        "shodan": bool(SHODAN_API_KEY),
        "hunter": bool(HUNTER_API_KEY),
        "gemini": bool(GEMINI_API_KEY)
    })

# CLI interface
def main():
    parser = argparse.ArgumentParser(description='Advanced Reconnaissance Tool')
    parser.add_argument('--target', '-t', help='Target domain or IP address')
    parser.add_argument('--server', '-s', action='store_true', help='Run as a web server')
    parser.add_argument('--port', '-p', type=int, default=5000, help='Port to run the web server on')
    parser.add_argument('--no-nmap', action='store_true', help='Skip Nmap scans')
    parser.add_argument('--no-dns', action='store_true', help='Skip DNS reconnaissance')
    parser.add_argument('--no-subdomains', action='store_true', help='Skip subdomain enumeration')
    parser.add_argument('--no-web', action='store_true', help='Skip web reconnaissance')
    parser.add_argument('--no-osint', action='store_true', help='Skip OSINT')
    parser.add_argument('--no-ports', action='store_true', help='Skip additional port scanners')
    parser.add_argument('--no-ssl-smb', action='store_true', help='Skip SSL and SMB scans')
    parser.add_argument('--no-hunter', action='store_true', help='Skip Hunter.io API')
    parser.add_argument('--no-shodan', action='store_true', help='Skip Shodan.io API')
    parser.add_argument('--no-gemini', action='store_true', help='Skip Gemini AI analysis')
    
    args = parser.parse_args()
    
    if args.server:
        print(f"Starting web server on port {args.port}")
        app.run(host='0.0.0.0', port=args.port, debug=True)
    elif args.target:
        options = {
            'nmap': not args.no_nmap,
            'dns': not args.no_dns,
            'subdomains': not args.no_subdomains,
            'web': not args.no_web,
            'osint': not args.no_osint,
            'ports': not args.no_ports,
            'ssl_smb': not args.no_ssl_smb,
            'hunter': not args.no_hunter,
            'shodan': not args.no_shodan,
            'gemini': not args.no_gemini
        }
        
        print(f"Starting reconnaissance on {args.target}")
        result = run_recon(args.target, options)
        print(f"Scan completed. Report saved to: {result['report_file']}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()