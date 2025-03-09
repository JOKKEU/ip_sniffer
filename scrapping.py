from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from bs4 import BeautifulSoup
import sys
import re

def parser(driver, ip, byte_value, file):
    driver.get(f"https://whatismyipaddress.com/ip/{ip}")
    try:
        wait = WebDriverWait(driver, 15)
        label_element = wait.until(EC.visibility_of_element_located((By.CLASS_NAME, "label")))

        html = driver.page_source
        soup = BeautifulSoup(html, "html.parser")

        details = {}
        details["IP"] = label_element.text.split(": ")[1] if ": " in label_element.text else "N/A"

        information = soup.find_all("p", class_="information")
        for info in information:
            spans = info.find_all("span")
            if len(spans) == 2:
                key = spans[0].text.strip()
                value = spans[1].text.strip() if spans[1] else "N/A"
                details[key] = value
                print(f"Extracted key-value pair: {key}: {value}")
                
        for key in details:
            file.write(f"{key}: {details.get(key, 'N/A')}\n")
        file.write(f"Received bytes from this IP: {byte_value}\n")
        file.write("\n\n")

    except Exception as e:
        print(f"An error occurred for IP {ip}: {e}")

def main():
    driver = None
    print("wait a little bit")
    if len(sys.argv) != 4:
        print("Use: python scrapping.py [browser (chrome or firefox)] [file for parsing data] [file for writing]")
        return
    
    browser = sys.argv[1]
    filename_for_parse = sys.argv[2]
    filename_for_write = sys.argv[3]

    try:
        if browser == "chrome":
            driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()))
        elif browser == "firefox":
            driver = webdriver.Firefox(service=FirefoxService(GeckoDriverManager().install()))
        else:
            print("Unsupported browser")
            return 
        
        with open(filename_for_parse, "r", encoding="utf-8") as file:
            content = file.read()
            ips = re.findall(r"(\d+\.\d+\.\d+\.\d+)", content)
            received_bytes = re.findall(r"Receive from this IP - (\d+) bytes", content)
        
        with open(filename_for_write, "w", encoding="utf-8") as file:
            for i, ip in enumerate(ips):
                byte_value = received_bytes[i] if i < len(received_bytes) else "N/A"
                parser(driver, ip, byte_value, file)

    except Exception as e:
        print(f"An error occurred while setting up the driver or parsing: {e}")
    finally:
        if driver:
            driver.quit()  

if __name__ == "__main__":
    main()
