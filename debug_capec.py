import requests
import xml.etree.ElementTree as ET

url = "https://capec.mitre.org/data/xml/capec_latest.xml"
print(f"📥 Загрузка {url}...")
response = requests.get(url, timeout=30)
content = response.content[:2000]  # Первые 2000 байт
print("📄 Начало XML:")
print(content.decode('utf-8', errors='ignore'))

# Попробуем распарсить
try:
    root = ET.fromstring(response.content)
    print(f"\n✅ Root tag: {root.tag}")
    # Ищем первые Attack_Pattern
    ns = {'capec': 'http://capec.mitre.org/capec-7'}
    patterns = root.findall('.//capec:Attack_Pattern', ns)
    print(f"🔍 Найдено с namespace: {len(patterns)}")
    patterns_no_ns = root.findall('.//Attack_Pattern')
    print(f"🔍 Найдено без namespace: {len(patterns_no_ns)}")
    
    if patterns:
        p = patterns[0]
        print(f"\n📋 Пример первого элемента:")
        print(f"  ID атрибут: {p.get('ID')}")
        name = p.find('.//capec:Name', ns)
        print(f"  Name: {name.text if name is not None else 'N/A'}")
except Exception as e:
    print(f"❌ Ошибка: {e}")