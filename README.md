step 1. git clone https://github.com/z0m31e-99/XSS-HUNTER
step 2. pip install -r requirements.txt
step 3. python main.py example.com
Optional arguments:

-o <outputfile>: Specify output HTML report filename (default: skull_report.html)
--headless: Run browser in headless mode (no GUI)
-d <depth>: Set crawl depth (default: 2)
Example with options:

python main.py example.com -o report.html --headless -d 3
