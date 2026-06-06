"""
Screenshot functionality
"""

from pathlib import Path
from datetime import datetime

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from webdriver_manager.chrome import ChromeDriverManager
    SCREENSHOTS_AVAILABLE = True
except ImportError:
    SCREENSHOTS_AVAILABLE = False

class ScreenshotTaker:
    def __init__(self, output_dir="reports"):
        self.output_dir = Path(output_dir)
        self.screenshots_enabled = SCREENSHOTS_AVAILABLE
        
        if not self.screenshots_enabled:
            print("\n[!] Screenshot functionality not available.")
            print("    Install with: pip install selenium webdriver-manager")
    
    def capture(self, html_file, domains_results):
        """Take a screenshot of the HTML report"""
        if not self.screenshots_enabled:
            return None
        
        try:
            print("[*] Taking screenshot...")
            
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--window-size=1400,2000')
            
            driver = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()), 
                options=options
            )
            
            driver.get(f"file://{html_file.absolute()}")
            
            # Wait for page to render
            import time
            time.sleep(2)
            
            # Generate screenshot filename
            screenshot_file = html_file.with_suffix('.png')
            driver.save_screenshot(str(screenshot_file))
            driver.quit()
            
            print(f"[✓] Screenshot saved: {screenshot_file}")
            
            return screenshot_file
            
        except Exception as e:
            print(f"[✗] Error creating screenshot: {e}")
            return None
