import re
import csv
import pandas as pd
from email import policy
from email.parser import BytesParser
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import matplotlib.pyplot as plt

# Rule 1: Flag Emails from Suspicious Domains
def is_suspicious_domain(sender):
    if not sender:
        return False
    suspicious_domains = ['hharvard.edu@gmail.com', 'cchristberkeley.edu@gmail.com', 'customercare@fedex.org', 'office@korloycompany.ro', 'jdoe@seedschoolmd.org', 'users@lists.sourceforge.net', 'penweltm@miamioh.edu']
    domain = sender.split('@')[-1]
    for sd in suspicious_domains:
        return any(domain.endswith(sd) )
    

# Rule 2: Detect the Use of Urgent Language
def contains_urgent_language(body):
    urgent_phrases = ['immediate action required', 'urgent', 'asap', 'act now', 'limited time']
    body_lower = body.lower()
    return any(phrase in body_lower for phrase in urgent_phrases)

# Rule 3: Identify URLs That Do Not Match the Legitimate Domain of the Sender
def mismatched_urls(sender, links):
    if not sender:
        return links
    domain = sender.split('@')[-1]
    return [link for link in links if domain not in link]

# Rule 4: Check for Attachments with Potentially Malicious File Types
def has_malicious_attachments(attachments):
    malicious_extensions = ['.exe', '.zip', '.scr', '.bat', '.cmd']
    return any(att.lower().endswith(ext) for att in attachments for ext in malicious_extensions)

# Rule 5: Identify Poorly Written Emails with Frequent Grammatical Errors
def contains_grammatical_errors(body):
    common_words = set(['the', 'and', 'is', 'in', 'it', 'you', 'that', 'he', 'was', 'for'])
    words = re.findall(r'\b\w+\b', body.lower())
    error_count = sum(1 for word in words if word not in common_words)
    total_words = len(words)
    error_rate = error_count / total_words
    return error_rate > 0.1  # Flag if more than 10% of words are errors

# Rule 6: Flag Emails with an Unfamiliar Greeting or Salutation
def greeting(body):
    common_greetings = [
        'dear', 'hello', 'hi', 'greetings', 'good morning', 'good afternoon', 'good evening'
    ]
    words = body.lower().split()[:3]
    return not any(greeting in words for greeting in common_greetings)

def request(body):
    common_greetings = [
        'verification', 'request', 'verify', 'click here'
    ]
    first_words = re.findall(r'\b\w+\b', body.lower())
    return not any(requests in first_words for requests in common_greetings)
# Function to parse the email content and headers
def parse_email(raw_email):
    msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    sender = msg.get('From')
    subject = msg.get('Subject')
    
    if msg.is_multipart():
        body = ''.join(
            part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8')
            for part in msg.iter_parts() if part.get_content_type() == 'text/plain'
        )
    else:
        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8')
    
    links = re.findall(r'http[s]?://\S+', body)
    attachments = [part.get_filename() for part in msg.iter_attachments() if part.get_filename()]
    
    # Debugging output
    print(f"Sender: {sender}")
    print(f"Subject: {subject}")
    print(f"Body: {body[:1000]}")  # Print first 1000 characters of the body for debugging
    
    return sender, subject, body, links, attachments

# Function to apply the detection rules
def detect_phishing(sender, subject, body, links, attachments):
    phishing_flags = {
        'suspicious_domain': is_suspicious_domain(sender),
        'urgent_language': contains_urgent_language(body),
        'mismatched_urls': len(mismatched_urls(sender, links)) > 0,
        'malicious_attachments': has_malicious_attachments(attachments),
        'grammatical_errors': contains_grammatical_errors(body),
        'greeting': greeting(body),
        'verification':request(body)
    }
    print("Phishing Flags:", phishing_flags)  # Debugging output
    return any(phishing_flags.values())

# Function to create a confusion matrix for a single sample email
def create_confusion_matrix(predicted_label,actual_labels):

    y_true = [actual_labels]
    y_pred = [predicted_label]
    cm = confusion_matrix(y_true, y_pred, labels=['phishing', 'legitimate'])


    
    # Extract TP, TN, FP, FN
    TN, FP, FN, TP = cm.ravel()
    
    # Print TP, TN, FP, FN
    print(f"True Positives (TP): {TP}")
    print(f"True Negatives (TN): {TN}")
    print(f"False Positives (FP): {FP}")
    print(f"False Negatives (FN): {FN}")
    
    # Calculate accuracy
    if (TP + TN + FP + FN) > 0:
        accuracy = (TP + TN) / (TP + TN + FP + FN)  
    else: 
        accuracy = 0
    print(f"Accuracy: {accuracy:.2f}")

    # Plot confusion matrix
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=['phishing', 'legitimate'])
    disp.plot(cmap=plt.cm.Blues)
    plt.title("Confusion Matrix")
    plt.show()

# Checking a single email
sample_email = """
From: hharvard.edu@gmail.com
Subject: Immediate Action Required
Body: Dearie Student,

Your access to your library account is expiring soon due to inactivity. To
continue to have access to the library services, you must reactivate your
account. For this purpose, click the web address below or copy and paste it
into your web browser. A successful login will activate your account and
you will be redirected to your library profile.

https://auth.berkeley.edu/cas/login?service=https%3a%2f%


If you are not able to login, please contact <Name Removed> at
xxxxx@berkeley.edu (link sends e-mail) for immediate assistance.
"""  # Replace with actual raw email content

# User input for actual label
actual_labels = input("Enter the actual label for the sample email ('phishing' or 'legitimate'): ").strip().lower()

# Check a single email
raw_email_bytes = sample_email.encode('latin1')
sender, subject, body, links, attachments = parse_email(raw_email_bytes)
predicted_label = 'phishing' if detect_phishing(sender, subject, body, links, attachments) else 'legitimate'

# Create and display confusion matrix
create_confusion_matrix(predicted_label,actual_labels)