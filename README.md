## A Machine Learning based malicious domain detection
![alt text](https://www.tesseract.global/images/LogoFull.png "Tessearct Global")
### Overview
A domain can be used for malicious purposes like 
- Malware, Virus or Trojan delivery
- Phishing
- Spam mails
- Malicious Ad Campaigns (Malvertising)
- Command and Control (C2C)
- DGA (Domain Generation Algorithms)
- Data Exfiltration etc.

So our idea was to develop an open source code to detect malicious domains using machine learning. We are using Scikit-learn, a free machine learning library for the python programming language.

Note here that we are detecting malicious domain not malicious URL, because we are focusing to prevent victims from attackers. The reason is 90% attacks are performed  using domain only, so if we detect malicious domain rather than malicious domain than actually we are stopping 90% attacks.   
### Problems
- There are many repositories are available to detect malicious url, phishing domains, DGA in github. But the problem we have seen is, for different attacks we have different solutions.
- Even though attacks have same behaviours in most of the attacks, we have different solutions.
- The repositories are not updated up to the mark.

So we have decided to consolidate these behaviours into single problem and develop a prediction model for the detection of malicious domains. Thus we don't have to rely on different solutions and maintaining different models.

### Dependencies
requirements.txt file contains actual dependencies to run this project. Install it using `pip install requirements.txt` command.

### Quick Start
To-Do

### Feature Least
1. URL length
2. Host length
3. Number of dots
4. Host ranking in city
5. Host ranking in country
6. URL average token length
7. Host average token length
8. Path average token length
9. URL token count (Considering words as a token)
10. Host token count
11. Path token count
12. URL largest token length
13. Host largest token length
14. Path largest token length   
15. IP address presence
16. ASN number
17. Safe browsing
18. Domain age
19. Number of subdomains
20. Is IDN (International Domain Name)

### To-Do
- Will add more machine learning models
- Will add Is domain from dynamic DNS as a feature
- Will add shortened URL as a feature
- Will add number of special characters (- and _) as a feature
- Will add website contents as a feature

### Results
     Testing Accuracy :: 94.67%
     Confusion Matrix :: [102, 4]
                         [5, 58]
                         
### Contributing
Feel free to fork and submit pull requests in [development](https://github.com/Nilesh1989/Detection-Of-Malicious-Domain/tree/developments).
 
### Refrences
- [Research paper by Doyen Sahoo, Chenghao Liu, Steven C.H. Hoi](https://arxiv.org/abs/1701.07179 "Malicious URL Detection using Machine Learning")
- Source code on github by [@vaseem-khan](https://github.com/vaseem-khan/URLcheck "Malicious Web Sites Detection using Suspicious URL")
- [Phishing Domain Detection with Machine Learning](https://www.normshield.com/phishing-domain-detection-with-machine-learning/ "NormShield")