#!/usr/bin/env python3
"""
RatPetShop - OWASP Top 10 Cybersecurity Lab
Entry point for the application
"""
from app.app import create_app

if __name__ == '__main__':
    app = create_app()
    print("\n" + "="*60)
    print("🐀 RatPetShop - OWASP Top 10 Cybersecurity Lab")
    print("="*60)
    print("\n⚠️  WARNING: This application contains intentional vulnerabilities!")
    print("   Use only in isolated environments for educational purposes.\n")
    print("📍 Starting server at: http://localhost:5000")
    print("👤 Default admin credentials:")
    print("   Username: admin")
    print("   Password: admin123\n")
    print("="*60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
