# src/parsers/capec_parser.py
import xml.etree.ElementTree as ET
import re
from config import Config
from parsers.base import BaseParser


class CAPECParser(BaseParser):
    """Парсер для CAPEC (XML формат, версия 3.x)"""
    
    NAMESPACE = "http://capec.mitre.org/capec-3"
    
    def parse(self, xml_content: bytes) -> list:
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            print(f"❌ Ошибка парсинга XML: {e}")
            return []
        
        results = []

        # Поиск с полным namespace {uri}tag
        patterns = root.findall(f'.//{{{self.NAMESPACE}}}Attack_Pattern')
        print(f"🔍 Найдено элементов Attack_Pattern: {len(patterns)}")

        # 🔹 Применяем лимит если включён 🔹
        limit = Config.MAX_CAPEC_RECORDS
        if limit and limit > 0 and len(patterns) > limit:
            patterns = patterns[:limit]
            print(f"⏱️ Применяем лимит: обрабатываем {limit}/{len(patterns)} записей")
        
        for idx, pattern in enumerate(patterns):
            item = self._parse_pattern(pattern)
            if item:
                results.append(item)
            if (idx + 1) % 100 == 0:
                print(f"  📊 Обработано: {idx + 1}/{len(patterns)}")
        
        print(f"📊 Итого записей: {len(results)}")
        return results
    
    def _get_text_content(self, elem) -> str:
        """Извлекает весь текстовый контент из элемента и всех вложенных тегов"""
        if elem is None:
            return ""
        # Собираем весь текст рекурсивно
        texts = []
        if elem.text and elem.text.strip():
            texts.append(elem.text.strip())
        for child in elem:
            texts.extend(self._get_text_content(child).split('\n'))
            if child.tail and child.tail.strip():
                texts.append(child.tail.strip())
        # Фильтруем пустые строки и объединяем
        return ' '.join(t for t in texts if t and t.strip()).strip()
    
    def _find_elements(self, parent, tag_name):
        """Находит элементы по имени тега с учётом namespace"""
        full_tag = f'{{{self.NAMESPACE}}}{tag_name}'
        return parent.findall(f'.//{full_tag}')
    
    def _parse_pattern(self, pattern) -> dict | None:
        try:
            capec_id = pattern.get("ID", "").strip()
            if not capec_id:
                return None
            
            item = {
                "id": f"CAPEC-{capec_id}",
                "name": pattern.get("Name", "").strip(),
                "description": "",
                "severity": "UNKNOWN",
                "related_cwe": [],
                "related_mitre": [],
                "prerequisites": [],
                "mitigations": []
            }
            
            # === Description ===
            desc_elems = self._find_elements(pattern, "Description")
            if desc_elems:
                item["description"] = self._get_text_content(desc_elems[0])
            
            # === Severity (Typical_Severity) ===
            sev_elems = self._find_elements(pattern, "Typical_Severity")
            if sev_elems and sev_elems[0].text:
                item["severity"] = sev_elems[0].text.strip().upper()
            
            # === Related CWE ===
            for ref in self._find_elements(pattern, "Related_Weakness"):
                cwe_id = ref.get("CWE_ID")
                if cwe_id:
                    item["related_cwe"].append(f"CWE-{cwe_id}")
            
            # === Related MITRE ATT&CK ===
            # ⚠️ В официальном CAPEC XML эти ссылки отсутствуют, оставляем пустым
            for ext_ref in self._find_elements(pattern, "External_Reference"):
                source_elem = self._find_elements(ext_ref, "Source")
                id_elem = self._find_elements(ext_ref, "External_ID")
                if source_elem and id_elem:
                    source = self._get_text_content(source_elem[0]).upper()
                    ext_id = self._get_text_content(id_elem[0])
                    if "ATT&CK" in source and re.match(r'^T\d{4}(\.\d{3})?$', ext_id):
                        item["related_mitre"].append(ext_id)
            
            # === Prerequisites ===
            for prereq in self._find_elements(pattern, "Prerequisite"):
                text = self._get_text_content(prereq)
                if text:
                    # Форматируем как в примере: "database_running"
                    formatted = text.lower().replace(" ", "_").replace(",", "").replace(".", "").replace("(", "").replace(")", "")
                    item["prerequisites"].append(formatted)
            
            # === Mitigations — ИСПРАВЛЕНО ===
            # Ищем все Solution_Or_Mitigation внутри Solutions_and_Mitigations
            mitigation_containers = self._find_elements(pattern, "Solutions_and_Mitigations")
            for container in mitigation_containers:
                for mitigation in self._find_elements(container, "Solution_Or_Mitigation"):
                    text = self._get_text_content(mitigation)
                    if text and len(text) > 15:  # Игнорируем слишком короткие фрагменты
                        item["mitigations"].append(text)
            
            # === Перевод (если включён в конфиге) ===
            if Config.ENABLE_TRANSLATION:
                if item["name"] and not self._is_russian(item["name"]):
                    item["name"] = self.translator.translate(item["name"])
                if item["description"] and not self._is_russian(item["description"]):
                    item["description"] = self.translator.translate(item["description"])
                item["mitigations"] = self.translator.translate_list(item["mitigations"])
            
            # === Очистка: убираем пробелы в концах значений (ключи уже чистые) ===
            cleaned = {}
            for k, v in item.items():
                if isinstance(v, str):
                    cleaned[k] = v.strip()
                elif isinstance(v, list):
                    cleaned[k] = [x.strip() if isinstance(x, str) else x for x in v]
                else:
                    cleaned[k] = v
            
            return cleaned
            
        except Exception as e:
            print(f"⚠️ Ошибка парсинга элемента {pattern.get('ID', 'UNKNOWN')}: {e}")
            return None
    
    def _is_russian(self, text: str) -> bool:
        return bool(re.search(r'[а-яА-ЯёЁ]', text))