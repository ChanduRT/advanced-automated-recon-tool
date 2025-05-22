# ReconMaster - Advanced Reconnaissance Tool

![ReconMaster Banner](https://img.shields.io/badge/ReconMaster-Advanced%20Reconnaissance-blue?style=for-the-badge)

A comprehensive web-based reconnaissance tool that combines traditional security tools with modern API integrations and AI-powered analysis. ReconMaster provides a professional interface for conducting authorized penetration testing and educational security research.

## 🚀 Features

### Core Capabilities
- **Web-based Interface**: Clean, responsive design accessible from any browser
- **Real-time Progress Tracking**: Live updates and tool output streaming
- **Comprehensive Scanning**: Integrates multiple reconnaissance tools
- **AI-Powered Analysis**: Gemini AI provides intelligent security insights
- **Professional Reports**: Detailed reports with executive summaries
- **API Integrations**: Hunter.io, Shodan.io, and Gemini AI

### Advanced Features
- **Parallel Processing**: Multiple tools run simultaneously for faster results
- **Live Output Display**: Real-time tool execution with syntax highlighting
- **Report Management**: Organized storage and retrieval of scan results
- **API Status Monitoring**: Visual indicators for service connectivity
- **Mobile Responsive**: Works on desktop and mobile devices

## 🛠 Prerequisites

### System Requirements
- Python 3.7+
- Linux/macOS (recommended) or Windows with WSL
- Web browser (Chrome, Firefox, Safari, Edge)
- Internet connection for API services

### Required Tools
The following tools should be installed on your system:
- `nmap` - Network exploration and security auditing
- `dnsrecon` - DNS enumeration tool
- `sublist3r` - Subdomain enumeration tool
- `nikto` - Web vulnerability scanner
- `wafw00f` - Web Application Firewall detection
- `dirb` - Web content scanner
- `gobuster` - Directory/file & DNS busting tool

### API Keys (Optional but Recommended)
- **Shodan API Key**: [Get from Shodan.io](https://shodan.io)
- **Hunter.io API Key**: [Get from Hunter.io](https://hunter.io)
- **Google Gemini API Key**: [Get from Google AI Studio](https://makersuite.google.com)

## 📦 Installation

### 1. Clone/Download the Project

```bash
mkdir reconmaster && cd reconmaster
```

### 2. Create Directory Structure

```bash
mkdir -p templates static/css static/js recon-output
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

**requirements.txt**:
```
flask>=2.3.0
flask-cors>=4.0.0
requests>=2.31.0
shodan>=1.29.0
google-generativeai>=0.3.0
python-dotenv>=1.0.0
subprocess32>=3.5.4
psutil>=5.9.0
```

### 4. Install System Tools

**Ubuntu/Debian**:
```bash
sudo apt update
sudo apt install nmap dnsrecon nikto dirb gobuster
pip install sublist3r
git clone https://github.com/EnableSecurity/wafw00f.git && cd wafw00f && python setup.py install
```

**macOS (with Homebrew)**:
```bash
brew install nmap nikto dirb gobuster
pip install sublist3r dnsrecon
git clone https://github.com/EnableSecurity/wafw00f.git && cd wafw00f && python setup.py install
```

### 5. Configure API Keys

Create a `.env` file in the root directory:

```bash
# API Keys Configuration
SHODAN_API_KEY=your_shodan_api_key_here
HUNTER_API_KEY=your_hunter_api_key_here
GEMINI_API_KEY=your_gemini_api_key_here

# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development
```

## 🚀 Usage

### Starting the Application

```bash
python app.py --server --port 5000
```

### Access the Web Interface

Open your browser and navigate to:
```
http://localhost:5000
```

### Basic Scan Process

1. **Enter Target**: Input the target domain or IP address
2. **Select Tools**: Choose from available reconnaissance tools
3. **Configure APIs**: Ensure API services are connected (optional)
4. **Start Scan**: Click "Start Reconnaissance" to begin
5. **Monitor Progress**: Watch real-time progress and tool outputs
6. **Review Results**: Analyze comprehensive reports with AI insights

### Command Line Options

```bash
python app.py [OPTIONS]

Options:
  --server          Start the web server
  --port PORT       Specify port number (default: 5000)
  --host HOST       Specify host address (default: 127.0.0.1)
  --debug           Enable debug mode
  --help            Show help message
```

## 📊 API Integrations

### Shodan.io Integration
- **Purpose**: Host information and vulnerability data
- **Features**: Open ports, services, CVEs, geographical data
- **Rate Limits**: Varies by plan (100 queries/month for free)

### Hunter.io Integration
- **Purpose**: Email intelligence and OSINT
- **Features**: Email enumeration, domain information, company data
- **Rate Limits**: 25 requests/month for free accounts

### Gemini AI Integration
- **Purpose**: Intelligent security analysis
- **Features**: Vulnerability assessment, recommendations, report summaries
- **Rate Limits**: Generous free tier available

## 📋 Available Tools

### Network Reconnaissance
- **Nmap**: Port scanning and service detection
- **DNS Recon**: DNS enumeration and record analysis

### Web Application Testing
- **Nikto**: Web vulnerability scanning
- **WAFW00f**: Web Application Firewall detection
- **Dirb**: Directory and file enumeration
- **Gobuster**: Fast directory/file bruteforcing

### Subdomain Discovery
- **Sublist3r**: Subdomain enumeration using OSINT

## 📁 File Structure

```
reconmaster/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env                  # Environment variables (create this)
├── templates/
│   └── index.html        # Main web interface
├── static/
│   ├── css/
│   │   └── style.css     # Stylesheet
│   └── js/
│       └── main.js       # JavaScript functionality
└── recon-output/         # Scan results and reports
    ├── reports/
    └── logs/
```

## 🔧 Configuration

### Environment Variables
- `SHODAN_API_KEY`: Your Shodan API key
- `HUNTER_API_KEY`: Your Hunter.io API key
- `GEMINI_API_KEY`: Your Google Gemini API key
- `FLASK_ENV`: Development or production
- `FLASK_APP`: Main application file

### Customization Options
- Modify tool parameters in `app.py`
- Adjust scan timeouts and intervals
- Customize report templates
- Add additional reconnaissance tools

## 📈 Reports and Output

### Report Types
- **Executive Summary**: High-level findings and recommendations
- **Technical Details**: Comprehensive tool outputs and data
- **Vulnerability Assessment**: Security issues and risk ratings
- **AI Analysis**: Gemini-powered insights and recommendations

### Export Formats
- HTML reports with interactive elements
- JSON data for programmatic access
- Plain text summaries
- CSV data exports

## ⚠️ Legal and Ethical Use

### Important Notice
This tool is designed for:
- **Authorized penetration testing**
- **Educational purposes**
- **Security research on owned systems**
- **Bug bounty programs with proper authorization**

### Prohibited Uses
- **Unauthorized scanning of systems**
- **Malicious activities**
- **Violation of terms of service**
- **Illegal reconnaissance**

### Disclaimer
Users are responsible for ensuring they have proper authorization before scanning any systems. The developers are not responsible for misuse of this tool.

## 🐛 Troubleshooting

### Common Issues

**API Keys Not Working**:
- Verify keys are correctly set in `.env` file
- Check API quotas and limits
- Ensure proper API permissions

**Tools Not Found**:
- Verify all required tools are installed
- Check system PATH configuration
- Install missing dependencies

**Port Already in Use**:
```bash
python app.py --server --port 8080
```

**Permission Errors**:
- Ensure proper file permissions
- Run with appropriate user privileges
- Check directory write permissions

### Debug Mode
Enable debug mode for detailed error information:
```bash
python app.py --server --debug
```

## 🤝 Contributing

### How to Contribute
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Development Setup
```bash
git clone <repository-url>
cd reconmaster
pip install -r requirements.txt
python app.py --server --debug
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔗 Resources

### Documentation
- [Nmap Documentation](https://nmap.org/docs.html)
- [Shodan API Documentation](https://developer.shodan.io/)
- [Hunter.io API Documentation](https://hunter.io/api-documentation)
- [Google Gemini API Documentation](https://ai.google.dev/)

### Security Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [SANS Penetration Testing Resources](https://www.sans.org/white-papers/)

## 🆘 Support

### Getting Help
- Check the troubleshooting section
- Review tool documentation
- Verify system requirements
- Ensure proper configuration

### Community
- Join security research communities
- Participate in bug bounty programs
- Contribute to open source security tools
- Share knowledge responsibly

---

**Made with ❤️ for the cybersecurity community**

*Remember: With great power comes great responsibility. Use this tool ethically and legally.*
