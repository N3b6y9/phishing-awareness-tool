!/usr/bin/env python3
"""
Email Phishing Awareness Tool with GUI
Author: Arjun Rajendra Kumar
Description: A GUI tool to detect and highlight phishing indicators in emails
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import re
import sys

class PhishingAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Phishing Awareness Tool")
        self.root.geometry("900x700")
        self.root.configure(bg="#f0f0f0")
        
        # Initialize analyzer patterns
        self.setup_patterns()
        
        # Create UI elements
        self.create_widgets()
        
    def setup_patterns(self):
        """Initialize regex patterns for phishing detection"""
        self.urgency_phrases = [
            r"urgent(?:ly)?", r"immediate(?:ly)?", r"action required", 
            r"account (?:verification|suspension|closure)", r"limited time",
            r"last warning", r"final notice", r"security alert", 
            r"your account", r"click below", r"verify your account",
            r"password expiry", r"unauthorized login attempt", r"dear (?:customer|user)",
            r"confirm your identity", r"banking alert", r"payment (?:failed|pending)",
            r"important notice", r"attention required", r"reactivate your account",
            r"update your information", r"billing information (?:needed|update)"
        ]
        
        self.suspicious_domains = [
            r"\.(?:xyz|top|club|loan|win|bid|tk|ml|ga|cf|gq|pw|cc|info|biz|review|account|support|security|verify|login|update)($|/)",
            r"\d+\.\d+\.\d+\.\d+",  # IP addresses
        ]
        
        self.generic_greetings = [
            r"dear (?:customer|user|valued customer|account holder|member)",
            r"hello (?:customer|user)",
            r"greetings (?:customer|user)",
            r"attention (?:customer|user|account holder)"
        ]
    
    def create_widgets(self):
        """Create the GUI interface"""
        # Title
        title_label = tk.Label(self.root, text="Email Phishing Awareness Tool", 
                              font=("Arial", 16, "bold"), bg="#f0f0f0", fg="#2c3e50")
        title_label.pack(pady=10)
        
        # Instructions
        instr_label = tk.Label(self.root, 
                              text="Paste email content below or load from file to analyze for phishing indicators:",
                              font=("Arial", 10), bg="#f0f0f0", fg="#34495e")
        instr_label.pack(pady=5)
        
        # Frame for email input
        input_frame = tk.LabelFrame(self.root, text="Email Content", padx=10, pady=10, 
                                   bg="#f0f0f0", fg="#2c3e50", font=("Arial", 10, "bold"))
        input_frame.pack(padx=20, pady=10, fill="both", expand=True)
        
        # Email input area
        self.email_text = scrolledtext.ScrolledText(input_frame, width=100, height=15, 
                                                   font=("Courier", 10), wrap=tk.WORD)
        self.email_text.pack(fill="both", expand=True)
        
        # Button frame
        button_frame = tk.Frame(self.root, bg="#f0f0f0")
        button_frame.pack(pady=10)
        
        # Load from file button
        load_btn = tk.Button(button_frame, text="Load from File", 
                            command=self.load_from_file, bg="#3498db", fg="white",
                            font=("Arial", 10), width=12, height=1)
        load_btn.pack(side=tk.LEFT, padx=5)
        
        # Analyze button
        analyze_btn = tk.Button(button_frame, text="Analyze Email", 
                               command=self.analyze_email, bg="#2ecc71", fg="white",
                               font=("Arial", 10), width=12, height=1)
        analyze_btn.pack(side=tk.LEFT, padx=5)
        
        # Clear button
        clear_btn = tk.Button(button_frame, text="Clear", 
                             command=self.clear_text, bg="#e74c3c", fg="white",
                             font=("Arial", 10), width=12, height=1)
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Results frame
        result_frame = tk.LabelFrame(self.root, text="Analysis Results", padx=10, pady=10,
                                    bg="#f0f0f0", fg="#2c3e50", font=("Arial", 10, "bold"))
        result_frame.pack(padx=20, pady=10, fill="both", expand=True)
        
        self.result_text = scrolledtext.ScrolledText(result_frame, width=100, height=15, 
                                                    bg="#ecf0f1", font=("Arial", 10), wrap=tk.WORD)
        self.result_text.pack(fill="both", expand=True)
        self.result_text.config(state=tk.DISABLED)
        
    def load_from_file(self):
        """Load email content from a file"""
        file_path = filedialog.askopenfilename(
            title="Select Email File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.email_text.delete(1.0, tk.END)
                    self.email_text.insert(tk.END, content)
                messagebox.showinfo("Success", "File loaded successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Could not read file: {e}")
    
    def clear_text(self):
        """Clear both text areas"""
        self.email_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        
    def analyze_email(self):
        """Analyze the email content for phishing indicators"""
        email_content = self.email_text.get("1.0", tk.END)
        
        if not email_content.strip():
            messagebox.showwarning("Input Error", "Please enter email content to analyze.")
            return
        
        # Perform analysis
        results = self.perform_analysis(email_content)
        
        # Display results
        self.display_results(results)
    
    def perform_analysis(self, email_text):
        """Analyze email text for phishing indicators"""
        results = {
            'suspicious_links': [],
            'urgency_phrases': [],
            'generic_greetings': [],
            'spoofed_sender': False,
            'overall_risk': 'Low'
        }
        
        # Check for urgency phrases
        for phrase in self.urgency_phrases:
            if re.search(phrase, email_text, re.IGNORECASE):
                results['urgency_phrases'].append(phrase)
        
        # Check for generic greetings
        for greeting in self.generic_greetings:
            if re.search(greeting, email_text, re.IGNORECASE):
                results['generic_greetings'].append(greeting)
        
        # Extract and check links
        link_pattern = re.compile(r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+)', re.IGNORECASE)
        links = link_pattern.findall(email_text)
        
        for link in links:
            for domain in self.suspicious_domains:
                if re.search(domain, link, re.IGNORECASE):
                    results['suspicious_links'].append(link)
                    break
        
        # Check for sender spoofing
        if re.search(r'from:.*<.*@.*>', email_text, re.IGNORECASE):
            results['spoofed_sender'] = True
        
        # Calculate overall risk
        risk_score = (len(results['suspicious_links']) * 3 + 
                     len(results['urgency_phrases']) * 2 + 
                     len(results['generic_greetings']) * 1 +
                     (5 if results['spoofed_sender'] else 0))
        
        if risk_score > 15:
            results['overall_risk'] = 'High'
        elif risk_score > 8:
            results['overall_risk'] = 'Medium'
        else:
            results['overall_risk'] = 'Low'
            
        return results
    
    def display_results(self, results):
        """Display analysis results in the results text area"""
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete("1.0", tk.END)
        
        # Create report
        report = "=" * 60 + "\n"
        report += "EMAIL PHISHING ANALYSIS REPORT\n"
        report += "=" * 60 + "\n\n"
        
        # Overall risk with color coding
        risk_color_tag = "risk_high" if results['overall_risk'] == 'High' else \
                        "risk_medium" if results['overall_risk'] == 'Medium' else "risk_low"
        
        report += f"Overall Risk Level: {results['overall_risk']}\n\n"
        
        # Detailed findings
        if results['suspicious_links']:
            report += "🔴 SUSPICIOUS LINKS DETECTED:\n"
            for link in results['suspicious_links']:
                report += f"   - {link}\n"
            report += "   Tip: Hover over links before clicking to see the actual URL.\n\n"
        
        if results['urgency_phrases']:
            report += "🔴 URGENCY PHRASES DETECTED:\n"
            for phrase in set(results['urgency_phrases']):
                report += f"   - '{phrase}'\n"
            report += "   Tip: Phishers often create a false sense of urgency to bypass your rational thinking.\n\n"
        
        if results['generic_greetings']:
            report += "🟡 GENERIC GREETINGS DETECTED:\n"
            for greeting in set(results['generic_greetings']):
                report += f"   - '{greeting}'\n"
            report += "   Tip: Legitimate organizations usually address you by name.\n\n"
        
        if results['spoofed_sender']:
            report += "🔴 POSSIBLE SPOOFED SENDER DETECTED:\n"
            report += "   - The sender address might be forged\n"
            report += "   Tip: Check the email headers carefully for discrepancies.\n\n"
        
        if not any([results['suspicious_links'], results['urgency_phrases'], 
                   results['generic_greetings'], results['spoofed_sender']]):
            report += "✅ No obvious phishing indicators detected.\n"
            report += "   However, always remain vigilant as phishing techniques evolve.\n\n"
        
        # Educational section
        report += "=" * 60 + "\n"
        report += "GENERAL PHISHING PREVENTION TIPS:\n"
        report += "=" * 60 + "\n"
        tips = [
            "1. Never click on suspicious links in emails",
            "2. Verify the sender's email address carefully",
            "3. Look for spelling and grammar mistakes",
            "4. Legitimate companies rarely ask for personal info via email",
            "5. Hover over links to see the actual destination URL",
            "6. When in doubt, contact the company directly using official channels",
            "7. Enable two-factor authentication on your accounts",
            "8. Keep your software and antivirus updated"
        ]
        
        for tip in tips:
            report += tip + "\n"
        
        # Insert report into text widget
        self.result_text.insert(tk.END, report)
        
        # Configure tags for colored text
        self.result_text.tag_configure("risk_high", foreground="#e74c3c", font=("Arial", 10, "bold"))
        self.result_text.tag_configure("risk_medium", foreground="#f39c12", font=("Arial", 10, "bold"))
        self.result_text.tag_configure("risk_low", foreground="#2ecc71", font=("Arial", 10, "bold"))
        
        # Apply risk color
        start_idx = self.result_text.search("Overall Risk Level:", "1.0", tk.END)
        if start_idx:
            end_idx = f"{start_idx}+{len('Overall Risk Level:')}c"
            risk_start = self.result_text.search(results['overall_risk'], end_idx, tk.END)
            if risk_start:
                risk_end = f"{risk_start}+{len(results['overall_risk'])}c"
                self.result_text.tag_add(risk_color_tag, risk_start, risk_end)
        
        self.result_text.config(state=tk.DISABLED)

def main():
    """Main function to run the application"""
    try:
        root = tk.Tk()
        app = PhishingAnalyzerGUI(root)
        root.mainloop()
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure Tkinter is installed: sudo apt install python3-tk")
        sys.exit(1)

if __name__ == "__main__":
    main()
