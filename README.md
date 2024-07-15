The problem 
"British Airways was compromised due to a vulnerability in a widely-used JavaScript library at the time, Modernizr version 2.6.2 min. Third-party JavaScript libraries can change without notice, even when hosted locally, leaving open the possibility of unauthorized modifications or injections of malicious code. Detecting changes can be difficult
This script currently fetches all script tags from a URL and lists them, subsequently looking for a listed version of JQuery.

References
https://pypi.org/project/beautifulsoup4/
https://www.crummy.com/software/BeautifulSoup/bs4/doc/

Links
Video Link:
https://youtu.be/ZHLBRLO0xHk 

Read Me::
https://github.com/asolis134/jquery_hound/blob/main/README.md 

Code:
https://github.com/asolis134/jquery_hound/blob/main/jquery_hound.py 

Future direction
Add monitoring for other popular JavaScript libraries along with CSS. Bootstrap is a library that has both CSS and JavaScript elements
Add the ability to add command line arguments. 
Allow a list of URLs to check for scripts.
Alerts to notify me that a vulnerable script has been found
Add a historical logging against a DB to help determine historically when scripts have changed.
