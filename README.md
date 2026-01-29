# 🐀 RatPetShop - OWASP Top 10 Cybersecurity Lab

An interactive cybersecurity training platform that demonstrates the OWASP Top 10 vulnerabilities through hands-on challenges. Perfect for learning web application security in a safe, controlled environment.

## ⚠️ Warning

**This application contains intentional security vulnerabilities for educational purposes only!**

- **DO NOT** deploy this application in a production environment
- **DO NOT** expose this application to the public internet
- **USE ONLY** in isolated, local development environments or VMs
- This is a training tool designed to teach security concepts through practice

## 🎯 Features

- **Three Difficulty Levels**: Easy, Medium, and Hard challenges with varying levels of guidance
- **OWASP Top 10 Coverage**: Learn about the most critical web application security risks
- **Capture The Flag (CTF)**: Find and submit flags to earn points
- **Scoreboard**: Track your progress and compete with others
- **Speedrun Mode**: Race against time to find randomly selected flags in a separate tenant
- **Guided Learning**: Easy challenges include detailed hints and step-by-step instructions
- **Interactive Dashboard**: Real-time activity feed and statistics
- **SQLite Database**: Automatically creates and manages its own database

## 📋 OWASP Top 10 Coverage

This lab covers the following OWASP Top 10 (2021) vulnerabilities:

1. **A01:2021 – Broken Access Control**
2. **A02:2021 – Cryptographic Failures**
3. **A03:2021 – Injection** (SQL Injection)
4. **A05:2021 – Security Misconfiguration**
5. **A07:2021 – Identification and Authentication Failures**
6. **A08:2021 – Software and Data Integrity Failures**
7. **A10:2021 – Server-Side Request Forgery (SSRF)**

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/The-XSS-Rat/RatPetShop.git
cd RatPetShop
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python run.py
```

The application will:
- Create the SQLite database automatically
- Seed initial data (challenges, admin user)
- Start the Flask development server on http://localhost:5000

## 🎮 How to Use

1. **Register an Account**: Create a new user account to start tracking your progress
2. **Explore Challenges**: Browse available challenges organized by difficulty level
3. **Read Descriptions**: Each challenge includes a description and hints
4. **Exploit Vulnerabilities**: Use your security knowledge to find the flags
5. **Submit Flags**: Enter found flags in the format `FLAG{...}` to earn points
6. **Track Progress**: Check the scoreboard to see your rank
7. **Try Speedrun Mode**: Test your skills in timed challenges with random flags

## 👤 Default Credentials

The application seeds a default admin account:
- **Username**: admin
- **Password**: admin123

(This is intentionally a weak password for demonstration purposes)

## 📁 Project Structure

```
RatPetShop/
├── app/
│   ├── models/          # Database models
│   ├── routes/          # Application routes
│   ├── static/          # CSS, JS, images
│   ├── templates/       # HTML templates
│   ├── utils/           # Utility functions
│   └── app.py           # Main application factory
├── requirements.txt     # Python dependencies
├── run.py              # Application entry point
└── README.md           # This file
```

## 🔧 Configuration

You can configure the application using environment variables:

- `SECRET_KEY`: Flask secret key (defaults to 'dev-secret-key-change-in-production')
- `DATABASE_URL`: Database URL (defaults to 'sqlite:///ratpetshop.db')
- `FLASK_DEBUG`: Set to '0' to disable debug mode (enabled by default for training purposes)

Example:
```bash
export SECRET_KEY="your-secret-key-here"
export DATABASE_URL="sqlite:///custom.db"
export FLASK_DEBUG="0"  # Disable debug mode
python run.py
```

**Note**: This application runs in debug mode by default for educational purposes. The debug mode is restricted to localhost (127.0.0.1) only to prevent external access to the Werkzeug debugger.

## 🎓 Learning Path

### For Beginners (Easy Challenges)
Start with easy challenges that include:
- Detailed descriptions
- Step-by-step hints
- Clear guidance on exploitation techniques

### For Intermediate Users (Medium Challenges)
Progress to medium challenges that require:
- More creative thinking
- Application of learned concepts
- Less direct guidance

### For Advanced Users (Hard Challenges)
Master hard challenges featuring:
- Complex vulnerability chains
- Advanced exploitation techniques
- Minimal hints

## 🏆 Speedrun Mode

Speedrun mode adds an exciting competitive element:
1. Select the number of flags (3, 5, 8, or 10)
2. Get a random set of challenges in a separate tenant
3. Race against time to find all flags
4. Compete for the fastest completion time on the leaderboard

## 🛡️ Security Considerations

This application is **intentionally vulnerable** for educational purposes. It includes:
- SQL Injection vulnerabilities
- Broken access control
- Weak authentication mechanisms
- Information disclosure
- And more...

**Never use this application's code patterns in real applications!**

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Add new challenges
- Improve documentation
- Fix bugs (non-security bugs in the framework)
- Enhance the UI/UX

## 📄 License

This project is open source and available for educational purposes.

## 🙏 Acknowledgments

- OWASP Foundation for the OWASP Top 10
- The cybersecurity community for continuous education efforts

## 📚 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Web Security Academy](https://portswigger.net/web-security)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)

---

**Remember**: This is a learning tool. Practice ethical hacking, never use these techniques on systems without permission!