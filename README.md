1. Clone the Repository

git clone https://github.com/z0m31e-99/XSS-HUNTER
cd XSS-HUNTER

2. Create and Activate a Virtual Environment (Recommended)

On Linux/macOS:
python3 -m venv venv
source venv/bin/activate

On Windows:
python -m venv venv
venv\Scripts\activate

3. Install Dependencies
pip install -r requirements.txt

4. Run the Tool
python main.py example.com

Option
Description
-o <outputfile>
Specify the output HTML report filename (default: skull_report.html)
--headless
Run browser in headless mode (without GUI)
-d <depth>
Set crawl depth (default: 2)

🔍 Example with Options:
python main.py example.com -o report.html --headless -d 3
